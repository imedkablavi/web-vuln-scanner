from __future__ import annotations

import ipaddress
from typing import Dict, List
from urllib.parse import urlparse

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


class SSRFPlugin(BasePlugin):
    """Bounded callback-proof SSRF detector.

    The detector never guesses loopback, cloud metadata, RFC1918, or link-local
    destinations. It requires an explicitly configured scanner-controlled callback
    URL and proof marker. External callbacks additionally require an explicit
    opt-in; loopback callbacks are sufficient for the local regression corpus.
    """

    name = "ssrf"
    supported_input_kinds = ["query", "body"]
    candidate_params = {
        "url",
        "uri",
        "endpoint",
        "callback",
        "webhook",
        "feed",
        "image_url",
        "avatar_url",
        "target_url",
    }

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    @classmethod
    def max_tests_per_surface(cls, config: Dict) -> int:
        try:
            return max(0, min(int(config.get("max_tests_per_surface", 1)), 1))
        except (TypeError, ValueError):
            return 1

    def _callback_url(self) -> str:
        return str(self.config.get("callback_url", "")).strip()

    def _expected_marker(self) -> str:
        return str(self.config.get("expected_marker", "")).strip()

    def _callback_allowed(self) -> bool:
        callback = self._callback_url()
        if not callback:
            return False
        parsed = urlparse(callback)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        if bool(self.config.get("allow_external_callback", False)):
            return True
        if parsed.hostname == "localhost":
            return True
        try:
            return ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            return False

    def _candidate_inputs(self, surface: AttackSurface):
        for name in sorted(self.candidate_params):
            if name in surface.params:
                yield name, "query"
        for field in surface.inputs:
            if field.name in self.candidate_params and field.kind in {"query", "body"}:
                yield field.name, field.kind

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(self._callback_allowed() and self._expected_marker() and any(self._candidate_inputs(surface)))

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        if not self._callback_allowed() or not self._expected_marker():
            return []
        for name, kind in self._candidate_inputs(surface):
            return [
                TestCase(
                    plugin=self.name,
                    surface_id=surface.id,
                    param=name,
                    kind=kind,
                    payload=self._callback_url(),
                    notes="scanner-controlled callback only; no internal-address guessing",
                )
            ]
        return []

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        marker = self._expected_marker()
        text = response.text or ""
        baseline_text = (baseline or {}).get("text", "")
        if not marker or marker not in text or marker in baseline_text:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        callback_host = urlparse(self._callback_url()).hostname or ""
        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "input_kind": testcase.kind,
                "callback_host": callback_host,
                "proof_marker_observed": True,
                "status": response.status_code,
            },
            {
                "method": surface_method(context),
                "param": testcase.param,
                "input_kind": testcase.kind,
                "payload_class": "scanner-controlled-callback",
                "callback_host": callback_host,
            },
            severity="HIGH",
            verification_status="verified",
            rationale="The target returned the scanner-controlled callback proof marker, demonstrating a server-side fetch.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Server-Side Request Forgery",
            title="Server-Side Request Forgery Verified",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Allowlist outbound destinations, resolve and validate addresses after redirects, and isolate server-side fetchers from sensitive networks.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-bounded",
            reproducible=True,
            notes=["Verified only against an explicitly configured scanner-controlled callback; blind SSRF is not claimed."],
        )


def surface_method(context: Dict) -> str:
    surface = context.get("surface") if isinstance(context, dict) else None
    return getattr(surface, "method", "GET") or "GET"
