from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding


class XXEVerifier:
    """Bounded external-entity verification using one scanner-controlled callback.

    This verifier never reads local files, probes cloud metadata, or guesses internal
    destinations. It only uses an explicitly configured HTTP(S) callback and requires
    the callback marker to be returned by the target as proof of entity resolution.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        self.config = config
        layer = config.get("active_verification", {}).get("xxe", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.callback_url = str(layer.get("callback_url", "") or "")
        self.expected_marker = str(layer.get("expected_marker", "") or "")
        self.allow_external_callback = bool(layer.get("allow_external_callback", False))
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, endpoint_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        endpoint = endpoint_url or self.endpoint_url
        if not self.enabled:
            return [], self._meta("XXE verification disabled.")
        if not endpoint:
            return [], self._meta("No explicit XML endpoint configured for XXE verification.")
        if not self.callback_url or not self.expected_marker:
            return [], self._meta("XXE verification requires callback_url and expected_marker.")
        if not self._callback_allowed():
            return [], self._meta("XXE callback blocked by verifier safety policy.")

        escaped = (
            self.callback_url.replace("&", "&amp;")
            .replace('"', "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE scanner [<!ENTITY scanner_xxe SYSTEM "{escaped}">]>'
            "<scanner>&scanner_xxe;</scanner>"
        )
        try:
            response = self.requester.send(
                "POST",
                endpoint,
                data=body,
                headers={
                    "Content-Type": "application/xml",
                    "Accept": "text/plain, application/xml, application/json",
                    "X-Scanner-Probe": "xxe-controlled-callback",
                },
                timeout=self.timeout,
                source="xxe_verification",
            )
        except Exception as exc:
            self.errors.append({"url": endpoint, "error": str(exc)})
            return [], self._meta()

        text = response.text or ""
        if self.expected_marker not in text:
            return [], self._meta()

        finding = Finding(
            plugin="xxe_verification",
            type="External XML Entity Resolution",
            title="External XML Entity Resolution Verified",
            category="injection",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"xxe:{endpoint}",
            url=endpoint,
            evidence={
                "status": response.status_code,
                "callback_marker_observed": True,
                "callback_class": "scanner-controlled",
                "probe_count": 1,
            },
            remediation=(
                "Disable external entity resolution and DTD processing for untrusted XML. "
                "Use hardened parser defaults and explicit allowlists for required schemas."
            ),
            reproduction={
                "method": "POST",
                "content_type": "application/xml",
                "payload_class": "scanner-controlled-external-entity",
                "request_count": 1,
            },
            verification_status="verified",
            scanner_mode="active-bounded",
            reproducible=True,
            target={"source": "explicit-xml-endpoint"},
        )
        return [finding], self._meta()

    def _callback_allowed(self) -> bool:
        try:
            parsed = urlparse(self.callback_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return False
            if self.allow_external_callback:
                return True
            if parsed.hostname == "localhost":
                return True
            ip = ipaddress.ip_address(parsed.hostname)
            return ip.is_loopback
        except (ValueError, TypeError):
            return False

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "endpoint_configured": bool(self.endpoint_url),
            "callback_configured": bool(self.callback_url and self.expected_marker),
            "external_callback_allowed": self.allow_external_callback,
            "max_requests": 1,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
