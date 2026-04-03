from __future__ import annotations

import asyncio
import os
import threading
from typing import Any, Dict, List
from urllib.parse import urlparse

from .models import AuthActor, SessionMaterial


class BrowserAuthEngine:
    def __init__(self, config, artifact_store=None, event_bus=None):
        self.config = config
        self.artifact_store = artifact_store
        self.event_bus = event_bus
        output_dir = config.get("output", {}).get("directory", "reports")
        self.artifacts_dir = os.path.join(output_dir, "browser_auth_artifacts")
        os.makedirs(self.artifacts_dir, exist_ok=True)

    def authenticate_actor(self, actor: AuthActor) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        error: Dict[str, Exception] = {}

        def _runner():
            try:
                result.update(asyncio.run(self._authenticate_actor(actor)))
            except Exception as exc:  # pragma: no cover - thread handoff safety
                error["exc"] = exc

        thread = threading.Thread(target=_runner, name=f"browser-auth-{actor.actor_id}", daemon=True)
        thread.start()
        thread.join()
        if error:
            raise error["exc"]
        return result

    async def _authenticate_actor(self, actor: AuthActor) -> Dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is required for browser-driven login. Install it before enabling browser auth.") from exc

        flow = actor.login_flow
        creds = {
            "username": actor.credentials.username_value or os.getenv(actor.credentials.username_env or "", ""),
            "password": actor.credentials.password_value or os.getenv(actor.credentials.password_env or "", ""),
        }
        if not creds["username"] or not creds["password"]:
            return {
                "success": False,
                "http_handoff_usable": False,
                "session_origin": "browser_authenticated_only",
                "evidence": {
                    "reason": "missing_credentials",
                    "login_url": flow.browser_login_url or flow.login_url,
                },
                "limitations": ["Browser-driven login credentials were not available from env placeholders or config values."],
            }

        browser_cfg = self.config.get("browser", {})
        login_url = flow.browser_login_url or flow.login_url
        verify_url = flow.verify_url or login_url
        headless = bool(browser_cfg.get("headless", True))
        slow_mo = int(browser_cfg.get("slow_mo", 0) or 0)

        screenshot_paths: List[str] = []
        trace_path = os.path.join(self.artifacts_dir, f"{actor.actor_id}-trace.zip")
        storage_state_path = os.path.join(self.artifacts_dir, f"{actor.actor_id}-storage.json")
        visited_urls: List[str] = []
        response_chain: List[Dict[str, Any]] = []
        limitations: List[str] = []
        material = SessionMaterial()

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless, slow_mo=slow_mo)
            context = await browser.new_context(ignore_https_errors=True, user_agent="WebVulnScanner/1.0")
            await context.tracing.start(screenshots=True, snapshots=True)
            page = await context.new_page()

            page.on(
                "response",
                lambda resp: response_chain.append(
                    {
                        "url": resp.url,
                        "status": resp.status,
                    }
                ),
            )

            try:
                await page.goto(login_url, wait_until="networkidle")
                visited_urls.append(page.url)
                for selector in flow.pre_submit_click_selectors:
                    await page.click(selector, timeout=2500)
                    await page.wait_for_timeout(250)
                username_selector = flow.username_selector or f'input[name="{flow.username_field}"]'
                password_selector = flow.password_selector or f'input[name="{flow.password_field}"]'
                submit_selector = flow.submit_selector or 'button[type="submit"], input[type="submit"], button'
                await page.fill(username_selector, creds["username"])
                await page.fill(password_selector, creds["password"])
                await self._capture_screenshot(page, actor.actor_id, "before-submit", screenshot_paths)
                await page.click(submit_selector, timeout=3500)
                await page.wait_for_load_state("networkidle")
                visited_urls.append(page.url)

                if flow.wait_for_url_contains:
                    await page.wait_for_url(lambda url: flow.wait_for_url_contains in url, timeout=5000)
                    visited_urls.append(page.url)
                if flow.success_selector:
                    await page.locator(flow.success_selector).wait_for(timeout=5000)
                for selector in flow.post_login_click_selectors:
                    await page.click(selector, timeout=2500)
                    await page.wait_for_load_state("networkidle")
                    visited_urls.append(page.url)

                matched_success_indicator = await self._matched_indicator(page, flow.success_indicators)
                matched_failure_indicator = await self._matched_indicator(page, flow.failure_indicators)

                verify_response = None
                if verify_url:
                    verify_response = await page.goto(verify_url, wait_until="networkidle")
                    visited_urls.append(page.url)
                await self._capture_screenshot(page, actor.actor_id, "after-login", screenshot_paths)
                await context.storage_state(path=storage_state_path)
                cookies = {item["name"]: item.get("value", "") for item in await context.cookies()}
                storage_dump = await page.evaluate(
                    """
                    (keys) => {
                      const result = { local: {}, session: {} };
                      const selected = Array.isArray(keys) ? keys : [];
                      for (const key of selected) {
                        const localValue = window.localStorage.getItem(key);
                        const sessionValue = window.sessionStorage.getItem(key);
                        if (localValue !== null) result.local[key] = localValue;
                        if (sessionValue !== null) result.session[key] = sessionValue;
                      }
                      return result;
                    }
                    """,
                    flow.browser_storage_keys,
                )

                access_token = ""
                refresh_token = ""
                if flow.auth_headers_template or flow.auth_scheme in {"json_login", "bearer_with_refresh", "static_bearer"}:
                    access_token = (
                        storage_dump.get("local", {}).get(flow.access_token_json_path)
                        or storage_dump.get("session", {}).get(flow.access_token_json_path)
                        or storage_dump.get("local", {}).get("access_token")
                        or storage_dump.get("session", {}).get("access_token")
                        or ""
                    )
                    refresh_token = (
                        storage_dump.get("local", {}).get(flow.refresh_token_json_path)
                        or storage_dump.get("session", {}).get(flow.refresh_token_json_path)
                        or storage_dump.get("local", {}).get("refresh_token")
                        or storage_dump.get("session", {}).get("refresh_token")
                        or ""
                    )
                material = SessionMaterial(
                    cookies=cookies,
                    access_token=str(access_token or ""),
                    refresh_token=str(refresh_token or ""),
                    storage_state_path=storage_state_path,
                )
                if material.access_token:
                    header_template = dict(flow.auth_headers_template or {})
                    if header_template:
                        material.headers = {
                            key: value.replace("{access_token}", material.access_token).replace("{refresh_token}", material.refresh_token)
                            for key, value in header_template.items()
                        }
                    if "Authorization" not in material.headers:
                        material.headers["Authorization"] = f"Bearer {material.access_token}"

                verify_status = getattr(verify_response, "status", 0) if verify_response is not None else 0
                verify_ok = bool(verify_response is not None and verify_status < 400 and "login" not in page.url.lower())
                if flow.success_indicators:
                    verify_ok = verify_ok and bool(matched_success_indicator)
                if matched_failure_indicator:
                    verify_ok = False
                usable_state = bool(material.cookies or material.access_token or material.storage_state_path)
                http_handoff_usable = bool(material.cookies or material.access_token)
                if not http_handoff_usable:
                    limitations.append("Browser login produced a storage state, but no reusable cookies or bearer token could be handed off to the HTTP layer.")

                evidence = {
                    "login_url": login_url,
                    "verify_url": verify_url,
                    "final_url": page.url,
                    "visited_urls": visited_urls,
                    "redirect_chain": response_chain[-10:],
                    "matched_success_indicator": matched_success_indicator,
                    "matched_failure_indicator": matched_failure_indicator,
                    "cookie_names": sorted(material.cookies.keys()),
                    "storage_state_path": storage_state_path,
                    "browser_storage_keys": flow.browser_storage_keys,
                    "storage_values": {key: list(value.keys()) for key, value in storage_dump.items()},
                    "verify_status": verify_status,
                    "usable_state": usable_state,
                    "http_handoff_usable": http_handoff_usable,
                    "screenshots": screenshot_paths,
                    "trace": trace_path,
                }
                if self.event_bus is not None:
                    self.event_bus.emit(
                        "browser_login",
                        {
                            "actor_id": actor.actor_id,
                            "login_url": login_url,
                            "verify_url": verify_url,
                            "success": bool(verify_ok and usable_state),
                            "http_handoff_usable": http_handoff_usable,
                        },
                    )
                return {
                    "success": bool(verify_ok and usable_state),
                    "http_handoff_usable": http_handoff_usable,
                    "material": material,
                    "evidence": evidence,
                    "limitations": limitations,
                    "session_origin": "browser_login" if http_handoff_usable else "browser_authenticated_only",
                }
            finally:
                await context.tracing.stop(path=trace_path)
                if self.artifact_store is not None:
                    self.artifact_store.register_file("trace", trace_path, actor_id=actor.actor_id, description="Browser login trace")
                    for screenshot_path in screenshot_paths:
                        self.artifact_store.register_file("screenshot", screenshot_path, actor_id=actor.actor_id, description="Browser login screenshot")
                    if os.path.exists(storage_state_path):
                        self.artifact_store.register_file("storage_state", storage_state_path, actor_id=actor.actor_id, description="Browser login storage state")
                await context.close()
                await browser.close()

    async def _matched_indicator(self, page, indicators: List[str]) -> str:
        if not indicators:
            return ""
        body_text = ""
        try:
            body_text = await page.locator("body").inner_text()
        except Exception:
            body_text = ""
        haystack = f"{page.url}\n{body_text}"
        for indicator in indicators:
            if indicator and indicator.lower() in haystack.lower():
                return indicator
        return ""

    async def _capture_screenshot(self, page, actor_id: str, label: str, bucket: List[str]):
        safe_host = urlparse(page.url).netloc.replace(":", "-") or "page"
        path = os.path.join(self.artifacts_dir, f"{actor_id}-{safe_host}-{label}.png")
        await page.screenshot(path=path, full_page=True)
        bucket.append(path)
