from __future__ import annotations

from typing import Dict, List

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


class SSTIPlugin(BasePlugin):
    """Bounded marker-only server-side template expression detector.

    This detector intentionally proves only arithmetic expression evaluation. It
    does not attempt command execution, file reads, object traversal, or sandbox
    escape. The plugin remains experimental until a broader deterministic corpus
    demonstrates acceptable false-positive/false-negative behavior.
    """

    name = "ssti"
    supported_input_kinds = ["query"]
    candidate_params = {
        "template",
        "view",
        "message",
        "name",
        "title",
        "content",
        "format",
        "text",
    }
    payload = "scanner{{1337*17}}canary"
    expected_render = "scanner22729canary"

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
                        notes="marker-only arithmetic expression; no command or file access",
                    )
                )
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        text = response.text or ""
        baseline_text = (baseline or {}).get("text", "")
        evaluated = self.expected_render in text and self.expected_render not in baseline_text
        raw_reflected = testcase.payload in text
        if not evaluated or raw_reflected:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "marker": self.expected_render,
                "status": response.status_code,
                "raw_payload_reflected": False,
            },
            {
                "method": "GET",
                "param": testcase.param,
                "payload_class": "arithmetic-template-marker",
            },
            severity="MEDIUM",
            verification_status="verified",
            rationale="The response contained the deterministic arithmetic-render marker while the raw template payload was absent.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Server-Side Template Expression Evaluation",
            title="Server-Side Template Expression Evaluation Detected",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Treat user-controlled values as data, not templates; use fixed templates and context-safe escaping.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-bounded",
            reproducible=True,
        )
