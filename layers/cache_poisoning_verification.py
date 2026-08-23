from __future__ import annotations

import secrets
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.models import Finding


class CachePoisoningVerifier:
    """Explicit opt-in cache-key verification using a unique canary URL.

    The verifier uses one reserved `.invalid` X-Forwarded-Host value and a unique
    query parameter so any cache entry is isolated to the scanner's canary key.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("cache_poisoning", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.url = str(layer.get("url", "") or "")
        self.canary_host = str(layer.get("canary_host", "scanner-cache-canary.invalid") or "")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 3)), 8.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        target = url or self.url
        if not self.enabled:
            return [], self._meta("Cache-poisoning verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("Cache-poisoning verification requires explicit_opt_in=true.")
        if not target:
            return [], self._meta("Cache-poisoning verification requires an explicit safe URL.")
        if not self.canary_host.endswith(".invalid"):
            return [], self._meta("Cache canary host must use the reserved .invalid suffix.")

        probe_url = self._with_canary_query(target)
        try:
            priming = self.requester.send(
                "GET",
                probe_url,
                headers={
                    "X-Forwarded-Host": self.canary_host,
                    "X-Scanner-Probe": "cache-prime",
                },
                timeout=self.timeout,
                source="cache_poisoning_verification",
            )
            replay = self.requester.send(
                "GET",
                probe_url,
                headers={"X-Scanner-Probe": "cache-replay"},
                timeout=self.timeout,
                source="cache_poisoning_verification",
            )
        except Exception as exc:
            self.errors.append({"url": target, "error": str(exc)})
            return [], self._meta()

        first_has_canary = self.canary_host in (priming.text or "")
        second_has_canary = self.canary_host in (replay.text or "")
        if not (priming.status_code < 400 and replay.status_code < 400 and first_has_canary and second_has_canary):
            return [], self._meta()

        finding = Finding(
            plugin="cache_poisoning_verification",
            type="Unkeyed Host Header Cache Poisoning",
            title="Cached Response Replays an Unkeyed X-Forwarded-Host Canary",
            category="cache",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"cache-poison:{target}",
            url=target,
            evidence={
                "priming_status": priming.status_code,
                "replay_status": replay.status_code,
                "canary_observed_during_priming": True,
                "canary_replayed_without_header": True,
                "header": "X-Forwarded-Host",
                "unique_cache_key_used": True,
            },
            remediation=(
                "Do not vary security-sensitive response content on untrusted forwarding headers unless those headers "
                "are normalized by a trusted proxy and included safely in the cache key. Purge affected cache entries."
            ),
            reproduction={
                "method": "GET",
                "request_count": 2,
                "prime_header": "X-Forwarded-Host",
                "canary_host_class": "reserved-invalid-domain",
                "unique_query_key": "__scanner_cache_canary",
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-safe-cache-url"},
        )
        return [finding], self._meta()

    @staticmethod
    def _with_canary_query(url: str) -> str:
        parsed = urlparse(url)
        query = list(parse_qsl(parsed.query, keep_blank_values=True))
        query.append(("__scanner_cache_canary", secrets.token_hex(8)))
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "url_configured": bool(self.url),
            "header": "X-Forwarded-Host",
            "canary_host_class": "reserved-invalid-domain",
            "max_requests": 2,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
