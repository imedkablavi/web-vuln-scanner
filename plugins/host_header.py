from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


class HostHeaderPlugin(BasePlugin):
    """Detect security-sensitive absolute URL generation from attacker Host input.

    Ordinary Host reflection is not enough. A result is reportable only when the
    canary host reaches a redirect destination or a security-sensitive absolute URL
    such as a reset/recovery/invite/login link.
    """

    name = "host_header"
    supported_input_kinds = ["header"]
    default_canary_host = "scanner-host-canary.invalid"
    default_path_hints = ("reset", "password", "recover", "forgot", "invite", "magic", "login", "host-header")
    sensitive_path_re = re.compile(r"/(?:reset|password|recover|forgot|invite|magic|login)(?:[/?#]|$)", re.IGNORECASE)

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    @classmethod
    def max_tests_per_surface(cls, config: Dict) -> int:
        return 1

    def _canary_host(self) -> str:
        host = str(self.config.get("canary_host", self.default_canary_host)).strip().lower()
        return host if host and "/" not in host and "://" not in host else self.default_canary_host

    def applicable(self, surface: AttackSurface) -> bool:
        if surface.method.upper() != "GET":
            return False
        path = (urlparse(surface.url).path or "/").lower()
        hints = tuple(str(item).lower() for item in self.config.get("path_hints", self.default_path_hints))
        return any(hint and hint in path for hint in hints)

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        if not self.applicable(surface):
            return []
        return [
            TestCase(
                plugin=self.name,
                surface_id=surface.id,
                param="Host",
                kind="header",
                payload=self._canary_host(),
                notes="inert reserved-domain Host canary",
            )
        ]

    def _location_uses_canary(self, location: str) -> bool:
        if not location:
            return False
        parsed = urlparse(location if "://" in location else f"https:{location}" if location.startswith("//") else "")
        return bool(parsed.hostname and parsed.hostname.lower() == self._canary_host())

    def _body_uses_sensitive_canary_url(self, body: str) -> bool:
        canary = re.escape(self._canary_host())
        for match in re.finditer(rf"https?://{canary}[^\s\"'<>]*", body or "", re.IGNORECASE):
            parsed = urlparse(match.group(0))
            if self.sensitive_path_re.search(parsed.path or "/"):
                return True
        return False

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        location = headers.get("location", "")
        body = response.text or ""
        baseline_headers = {str(k).lower(): str(v) for k, v in ((baseline or {}).get("headers", {}) or {}).items()}
        baseline_text = (baseline or {}).get("text", "")

        location_signal = self._location_uses_canary(location) and not self._location_uses_canary(baseline_headers.get("location", ""))
        body_signal = self._body_uses_sensitive_canary_url(body) and not self._body_uses_sensitive_canary_url(baseline_text)
        if not (location_signal or body_signal):
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "canary_host": self._canary_host(),
                "location_signal": location_signal,
                "sensitive_absolute_url_signal": body_signal,
                "status": response.status_code,
            },
            {
                "method": "GET",
                "header": "Host",
                "payload_class": "reserved-domain-host-canary",
            },
            severity="MEDIUM",
            verification_status="verified",
            rationale="The canary Host value influenced a redirect or security-sensitive absolute URL, not merely reflected text.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Host Header Trust",
            title="Host Header Influences Security-Sensitive URL Generation",
            category="misconfiguration",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Use a configured canonical origin for security-sensitive URLs and validate Host/Forwarded headers at trusted proxy boundaries.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-bounded",
            reproducible=True,
        )
