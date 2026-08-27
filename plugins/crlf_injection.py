from __future__ import annotations

from typing import Dict, List

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


class CRLFInjectionPlugin(BasePlugin):
    """Bounded response-header injection detector using a synthetic canary.

    The payload only attempts to create one inert response header. It does not
    inject cookies, redirects, scripts, cache directives, or executable content.
    """

    name = "crlf_injection"
    supported_input_kinds = ["query"]
    candidate_params = {"next", "url", "redirect", "return", "filename", "download"}
    marker_header = "X-Scanner-Canary"
    marker_value = "crlf-safe-marker"
    payload = f"scanner\r\n{marker_header}: {marker_value}"

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    @classmethod
    def max_tests_per_surface(cls, config: Dict) -> int:
        try:
            return max(0, min(int(config.get("max_tests_per_surface", 2)), 2))
        except (TypeError, ValueError):
            return 2

    def applicable(self, surface: AttackSurface) -> bool:
        return any(name in surface.params for name in self.candidate_params)

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        tests: List[TestCase] = []
        for name in sorted(self.candidate_params):
            if name in surface.params:
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind="query",
                        payload=self.payload,
                        notes="inert response-header canary only",
                    )
                )
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        response_headers = {str(k).lower(): str(v) for k, v in getattr(response, "headers", {}).items()}
        baseline_headers = {
            str(k).lower(): str(v) for k, v in ((baseline or {}).get("headers", {}) or {}).items()
        }
        key = self.marker_header.lower()
        injected = response_headers.get(key) == self.marker_value and baseline_headers.get(key) != self.marker_value
        if not injected:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "injected_header": self.marker_header,
                "marker_value": self.marker_value,
                "status": response.status_code,
            },
            {
                "method": "GET",
                "param": testcase.param,
                "payload_class": "inert-crlf-header-canary",
            },
            severity="MEDIUM",
            verification_status="verified",
            rationale="The synthetic response header appeared only after the bounded CRLF canary was supplied.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="CRLF Response Header Injection",
            title="Response Header Injection Detected",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Reject CR/LF in header-bound values and use framework header APIs that prohibit response splitting.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-bounded",
            reproducible=True,
        )
