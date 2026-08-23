from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit, urlunsplit

from .scope import ScopePolicy


_FETCH_RE = re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_AXIOS_RE = re.compile(
    r"\baxios\.(get|post|put|patch|delete|head)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_XHR_RE = re.compile(
    r"\.open\s*\(\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_GENERIC_ROUTE_RE = re.compile(
    r"['\"]((?:https?://[^'\"\s]+|/(?:api|graphql|rest|v\d+)(?:/[^'\"\s]*)?))['\"]",
    re.I,
)
_STATIC_SUFFIXES = (
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


class JavaScriptEndpointDiscoverer:
    """Extract likely HTTP endpoints from JavaScript without executing it."""

    def __init__(self, requester, config: Dict[str, Any]):
        crawler_cfg = config.get("crawler", {})
        js_cfg = crawler_cfg.get("javascript_discovery", {})
        self.enabled = bool(js_cfg.get("enabled", True))
        self.max_scripts = int(js_cfg.get("max_scripts", 10))
        self.max_script_bytes = int(js_cfg.get("max_script_bytes", 250_000))
        self.max_endpoints = int(js_cfg.get("max_endpoints", 100))
        self.requester = requester
        self.scope_policy = getattr(requester, "scope_policy", None) or ScopePolicy(config)
        self.scripts_fetched = 0
        self.inline_scripts_scanned = 0
        self.external_scripts_seen = 0
        self.errors: List[Dict[str, str]] = []
        self._entries: Dict[tuple[str, str], Dict[str, str]] = {}

    @staticmethod
    def _canonical_url(base_url: str, candidate: str) -> str:
        candidate = str(candidate or "").strip()
        if not candidate or candidate.startswith(("javascript:", "data:", "mailto:", "tel:")):
            return ""
        if any(token in candidate for token in ("${", "{{", "<%")):
            return ""
        absolute = urljoin(base_url, candidate)
        parsed = urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        path_lower = (parsed.path or "").lower()
        if path_lower.endswith(_STATIC_SUFFIXES):
            return ""
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))

    def _add(self, base_url: str, candidate: str, method: str, source: str) -> None:
        if len(self._entries) >= self.max_endpoints:
            return
        url = self._canonical_url(base_url, candidate)
        if not url or not self.scope_policy.is_allowed(url, resolve_dns=False):
            return
        normalized_method = str(method or "GET").upper()
        key = (normalized_method, url)
        self._entries.setdefault(
            key,
            {
                "method": normalized_method,
                "url": url,
                "source": source,
            },
        )

    def _scan_text(self, text: str, base_url: str, source: str) -> None:
        sample = str(text or "")[: self.max_script_bytes]
        for candidate in _FETCH_RE.findall(sample):
            self._add(base_url, candidate, "GET", source)
        for method, candidate in _AXIOS_RE.findall(sample):
            self._add(base_url, candidate, method, source)
        for method, candidate in _XHR_RE.findall(sample):
            self._add(base_url, candidate, method, source)
        for candidate in _GENERIC_ROUTE_RE.findall(sample):
            self._add(base_url, candidate, "GET", source)

    def discover_from_soup(self, soup, base_url: str, actor=None) -> List[Dict[str, str]]:
        if not self.enabled:
            return self.entries()

        for script in soup.find_all("script"):
            inline = script.string or script.get_text() or ""
            if inline.strip():
                self.inline_scripts_scanned += 1
                self._scan_text(inline, base_url, "inline-script")

            src = script.get("src")
            if not src:
                continue
            self.external_scripts_seen += 1
            if self.scripts_fetched >= self.max_scripts:
                continue
            script_url = urljoin(base_url, src)
            if not self.scope_policy.is_allowed(script_url, resolve_dns=False):
                continue
            try:
                if actor is not None and hasattr(self.requester, "send_as_actor"):
                    response = self.requester.send_as_actor("GET", script_url, actor=actor)
                else:
                    response = self.requester.send("GET", script_url)
            except Exception as exc:
                self.errors.append({"url": script_url, "error": str(exc)})
                continue
            self.scripts_fetched += 1
            if response is None or int(getattr(response, "status_code", 0) or 0) != 200:
                continue
            self._scan_text(
                str(getattr(response, "text", "") or ""),
                script_url,
                "external-script",
            )
        return self.entries()

    def entries(self) -> List[Dict[str, str]]:
        return list(self._entries.values())[: self.max_endpoints]

    def report(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "scripts_fetched": self.scripts_fetched,
            "inline_scripts_scanned": self.inline_scripts_scanned,
            "external_scripts_seen": self.external_scripts_seen,
            "endpoints_discovered": len(self._entries),
            "sample_endpoints": self.entries()[:20],
            "errors": self.errors[:20],
            "limits": {
                "max_scripts": self.max_scripts,
                "max_script_bytes": self.max_script_bytes,
                "max_endpoints": self.max_endpoints,
            },
        }
