from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.models import Finding
from core.scope import ScopePolicy


class BrowserXSSVerifier:
    """Confirm reflected XSS with a harmless DOM marker in a real browser.

    Only GET/query candidates are tested. The payload changes one attribute on
    document.documentElement and performs no external fetch, storage write,
    cookie access, form submission, or application action.
    """

    def __init__(self, config):
        self.config = config
        browser_cfg = config.get("browser", {})
        layer = browser_cfg.get("xss_verification", {})
        self.enabled = bool(layer.get("enabled", False))
        self.max_tests = max(0, int(layer.get("max_tests", 3)))
        self.timeout_ms = max(1000, int(layer.get("timeout_ms", 8000)))
        self.scope_policy = ScopePolicy(config)
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []
        self.blocked_requests: List[str] = []
        self.tests_run = 0

    @staticmethod
    def _query_params(url: str) -> list[str]:
        result = []
        seen = set()
        for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if name not in seen:
                seen.add(name)
                result.append(name)
        return result

    @staticmethod
    def _marker(url: str, param: str) -> str:
        digest = hashlib.sha256(f"{url}:{param}".encode("utf-8")).hexdigest()[:12]
        return f"wvs-xss-{digest}"

    @staticmethod
    def _build_url(url: str, param: str, payload: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated = []
        for key, value in pairs:
            if key == param and not replaced:
                updated.append((key, payload))
                replaced = True
            else:
                updated.append((key, value))
        if not replaced:
            updated.append((param, payload))
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                urlencode(updated),
                parsed.fragment,
            )
        )

    def verify(self, snapshots: List[Dict[str, Any]]) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta()

        candidates = []
        for snapshot in snapshots:
            content_type = str(snapshot.get("content_type") or "").lower()
            text = str(snapshot.get("text") or "")
            if "html" not in content_type and "<html" not in text.lower():
                continue
            url = str(snapshot.get("url") or "")
            for param in self._query_params(url):
                if len(candidates) >= self.max_tests:
                    break
                marker = self._marker(url, param)
                payload = (
                    '<svg onload="document.documentElement.setAttribute('
                    f"'data-wvs-xss','{marker}'"
                    ')"></svg>'
                )
                candidates.append(
                    {
                        "url": url,
                        "param": param,
                        "marker": marker,
                        "payload": payload,
                        "probe_url": self._build_url(url, param, payload),
                    }
                )
            if len(candidates) >= self.max_tests:
                break

        if not candidates:
            return [], self._meta()

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._run_sync, candidates)
                results = future.result(
                    timeout=max(10, ((self.timeout_ms * len(candidates)) // 1000) + 10)
                )
        except FutureTimeout:
            self.errors.append({"check": "browser_xss", "error": "verification_timeout"})
            return [], self._meta()
        except Exception as exc:
            self.errors.append({"check": "browser_xss", "error": str(exc)})
            return [], self._meta()

        findings = []
        for candidate, result in zip(candidates, results):
            self.tests_run += 1
            if not result.get("confirmed"):
                continue
            findings.append(
                Finding(
                    plugin="browser_xss",
                    type="Reflected Cross-Site Scripting",
                    title="Reflected XSS Execution Confirmed",
                    category="xss",
                    severity="HIGH",
                    confidence="HIGH",
                    surface_id=(
                        f"browser-xss:{candidate['url']}:{candidate['param']}"
                    ),
                    url=candidate["url"],
                    evidence={
                        "parameter": candidate["param"],
                        "marker": candidate["marker"],
                        "browser_execution": True,
                        "final_url": result.get("final_url", ""),
                    },
                    remediation=(
                        "Encode untrusted data for its exact HTML context and avoid placing it in executable "
                        "markup or event-handler contexts. Use CSP as defense in depth rather than as the primary fix."
                    ),
                    reproduction={
                        "method": "GET",
                        "url": candidate["url"],
                        "param": candidate["param"],
                        "payload": candidate["payload"],
                    },
                    verification_status="verified",
                    scanner_mode="full-authorized-browser",
                    reproducible=True,
                    target={
                        "source": "browser-xss",
                        "method": "GET",
                        "parameter": candidate["param"],
                    },
                    notes=[
                        "Chromium executed an inert inline handler that only set a DOM attribute. No external request, storage access, cookie read, form submission, or application action was used."
                    ],
                )
            )
        return findings, self._meta()

    def _run_sync(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed for browser XSS verification") from exc

        results = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="WebVulnScanner/1.0",
                service_workers="block",
            )

            def route_handler(route, request):
                parsed = urlsplit(request.url)
                if parsed.scheme not in {"http", "https"}:
                    route.continue_()
                    return
                try:
                    allowed = self.scope_policy.is_allowed(
                        request.url,
                        resolve_dns=True,
                    )
                except Exception:
                    allowed = False
                if allowed:
                    route.continue_()
                    return
                if request.url not in self.blocked_requests:
                    self.blocked_requests.append(request.url)
                route.abort("blockedbyclient")

            context.route("**/*", route_handler)
            try:
                for candidate in candidates:
                    page = context.new_page()
                    try:
                        page.goto(
                            candidate["probe_url"],
                            wait_until="domcontentloaded",
                            timeout=self.timeout_ms,
                        )
                        page.wait_for_timeout(200)
                        value = page.evaluate(
                            "document.documentElement.getAttribute('data-wvs-xss')"
                        )
                        results.append(
                            {
                                "confirmed": value == candidate["marker"],
                                "final_url": page.url,
                            }
                        )
                    except Exception as exc:
                        results.append(
                            {
                                "confirmed": False,
                                "error": str(exc),
                                "final_url": getattr(page, "url", ""),
                            }
                        )
                    finally:
                        page.close()
            finally:
                context.close()
                browser.close()
        return results

    def _meta(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "tests_run": self.tests_run,
            "max_tests": self.max_tests,
            "blocked_requests": self.blocked_requests[:25],
            "errors": self.errors,
            "skipped": self.skipped,
        }
