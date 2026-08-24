from __future__ import annotations

import secrets
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.models import Finding


class WebCacheDeceptionVerifier:
    """Bounded authenticated web-cache-deception verifier.

    The operator supplies the exact deceptive URL and a marker known to exist in
    the authorized synthetic response. The verifier isolates its two requests
    with a unique query key and requires a cache-hit signal on the anonymous replay.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("web_cache_deception", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.url = str(layer.get("url", "") or "")
        self.private_marker = str(layer.get("private_marker", "") or "")
        self.cache_hit_header = str(layer.get("cache_hit_header", "X-Cache") or "X-Cache")
        self.cache_hit_value = str(layer.get("cache_hit_value", "HIT") or "HIT")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("Web cache deception verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("Web cache deception verification requires explicit_opt_in=true.")
        if not self.url or not self.private_marker:
            return [], self._meta("Web cache deception verification requires url and private_marker.")

        auth_cfg = dict(self.requester.config.get("auth", {}) or {})
        auth_headers = dict(auth_cfg.get("headers", {}) or {})
        auth_cookies = dict(auth_cfg.get("cookies", {}) or {})
        if not auth_headers and not auth_cookies:
            return [], self._meta("Web cache deception verification requires configured authorized auth material.")

        isolated_url = self._isolated_url(self.url)
        anonymous_headers = {name: "" for name in auth_headers}
        try:
            baseline = self.requester.send(
                "GET",
                isolated_url,
                headers={**auth_headers, "X-Scanner-Probe": "wcd-authenticated"},
                cookies=auth_cookies,
                timeout=self.timeout,
                source="web_cache_deception_verification",
            )
            anonymous = self.requester.send(
                "GET",
                isolated_url,
                headers={**anonymous_headers, "X-Scanner-Probe": "wcd-anonymous-replay"},
                cookies={},
                timeout=self.timeout,
                source="web_cache_deception_verification",
            )
        except Exception as exc:
            self.errors.append({"url": self.url, "error": str(exc)})
            return [], self._meta()

        baseline_private = baseline.status_code < 400 and self.private_marker in (baseline.text or "")
        anonymous_private = anonymous.status_code < 400 and self.private_marker in (anonymous.text or "")
        cache_hit = str(anonymous.headers.get(self.cache_hit_header, "") or "").upper() == self.cache_hit_value.upper()
        if not (baseline_private and anonymous_private and cache_hit):
            return [], self._meta()

        finding = Finding(
            plugin="web_cache_deception_verification",
            type="Web Cache Deception",
            title="Authenticated Response Replayed From Cache to Anonymous Request",
            category="data-exposure",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"wcd:{self.url}",
            url=self.url,
            evidence={
                "authenticated_private_marker_seen": True,
                "anonymous_private_marker_seen": True,
                "anonymous_cache_hit": True,
                "unique_cache_key_used": True,
                "private_marker_recorded": False,
                "auth_values_recorded": False,
            },
            remediation=(
                "Do not cache authenticated/private responses at shared-cacheable paths. Key caches on authorization state "
                "where appropriate, use Cache-Control: private/no-store, and normalize or reject deceptive path suffixes."
            ),
            reproduction={
                "request_count": 2,
                "unique_query_isolation": True,
                "marker_value_recorded": False,
                "auth_values_recorded": False,
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-deceptive-cache-url"},
        )
        return [finding], self._meta()

    @staticmethod
    def _isolated_url(url: str) -> str:
        parsed = urlparse(url)
        query = list(parse_qsl(parsed.query, keep_blank_values=True))
        query.append(("scanner_wcd", secrets.token_hex(8)))
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "max_requests": 2,
            "unique_cache_key": True,
            "private_marker_persisted": False,
            "auth_values_persisted": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
