from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlparse, urlunparse

from core.models import Finding
from core.browser_engine import BrowserEngine


class DOMXSSVerifier:
    """Browser verification for location.hash -> executable DOM sinks.

    The canary JavaScript performs one inert side effect only: it sets a data
    attribute on the current document. It performs no network request, storage
    access, cookie access, data extraction, navigation, or persistence.
    """

    token = "domxss-browser-canary"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        layer = config.get("browser", {}).get("dom_xss", {})
        self.enabled = bool(layer.get("enabled", False))
        self.max_urls = max(0, min(int(layer.get("max_urls", 3)), 5))
        self.timeout_ms = max(500, min(int(layer.get("timeout_ms", 3000)), 5000))
        self.errors: List[Dict[str, Any]] = []
        self.checked: List[str] = []

    def _payload(self) -> str:
        return (
            "<svg onload=\"document.documentElement.setAttribute('data-scanner-domxss',"
            f"'{self.token}')\"></svg>"
        )

    def _target_with_fragment(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=quote(self._payload(), safe="")))

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        scope = self.config.get("scope", {})
        for prefix in scope.get("exclude_paths", []) or []:
            if parsed.path.startswith(str(prefix)):
                return False
        include = list(scope.get("include_domains", []) or [])
        if not include:
            return True
        host = parsed.netloc
        hostname = parsed.hostname
        for item in include:
            item = str(item)
            if item.startswith("*.") and hostname.endswith(item[1:]):
                return True
            if host == item or hostname == item:
                return True
        return False

    async def scan(self, urls: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta(skipped="DOM-XSS browser verification disabled by configuration.")

        browser_config = deepcopy(self.config)
        browser_config.setdefault("browser", {})
        browser_config["browser"]["capture_trace"] = False
        browser_config["browser"]["capture_screenshots"] = False
        browser_config["browser"]["max_pages"] = max(1, self.max_urls)
        browser = BrowserEngine(browser_config)
        findings: List[Finding] = []
        try:
            await browser.start()
            seen = set()
            for raw_url in urls:
                if len(seen) >= self.max_urls:
                    break
                parsed = urlparse(raw_url)
                canonical = urlunparse(parsed._replace(fragment=""))
                if canonical in seen or not self._in_scope(canonical):
                    continue
                seen.add(canonical)
                self.checked.append(canonical)
                finding = await self._verify_url(browser, canonical)
                if finding is not None:
                    findings.append(finding)
        finally:
            try:
                await browser.stop()
            except Exception as exc:
                self.errors.append({"kind": "browser-stop", "error": str(exc)})
        return findings, self._meta()

    async def _verify_url(self, browser: BrowserEngine, url: str) -> Finding | None:
        target = self._target_with_fragment(url)
        page = await browser.context.new_page()
        try:
            await page.goto(target, wait_until="domcontentloaded", timeout=self.timeout_ms)
            await page.wait_for_timeout(150)
            executed = await page.evaluate(
                "token => document.documentElement.getAttribute('data-scanner-domxss') === token",
                self.token,
            )
            if not executed:
                return None
            return Finding(
                plugin="dom_xss_verification",
                type="DOM-Based Cross-Site Scripting",
                title="DOM-XSS JavaScript Execution Verified",
                category="injection",
                severity="HIGH",
                confidence="HIGH",
                surface_id=f"dom-xss:{url}",
                url=url,
                evidence={
                    "source": "location.hash",
                    "canary_executed": True,
                    "marker": self.token,
                    "network_callback_used": False,
                    "storage_or_cookie_access_used": False,
                },
                remediation="Do not pass location-derived strings to HTML/JS execution sinks. Prefer textContent/DOM APIs and context-appropriate sanitization.",
                reproduction={
                    "browser": "chromium",
                    "source": "location.hash",
                    "payload_class": "inert-dom-execution-canary",
                    "request_count": 1,
                },
                verification_status="verified",
                scanner_mode="browser-verification",
                reproducible=True,
                notes=["This check proves fragment-driven DOM JavaScript execution only; stored DOM-XSS and other sources are not claimed."],
            )
        except Exception as exc:
            self.errors.append({"kind": "dom-xss", "url": url, "error": str(exc)})
            return None
        finally:
            await page.close()

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "checked_urls": list(self.checked),
            "max_urls": self.max_urls,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
