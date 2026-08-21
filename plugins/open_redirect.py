from __future__ import annotations

from typing import List, Dict

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


class OpenRedirectPlugin(BasePlugin):
    name = "open_redirect"
    supported_input_kinds = ["query"]
    candidate_params = ["next", "url", "redirect", "return", "continue"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface, context=None):
        return any(p in surface.params for p in self.candidate_params)

    def generate_tests(self, surface, context: Dict) -> List[TestCase]:
        tests = []
        for name in self.candidate_params:
            if name in surface.params:
                payload = f"https://example.org/{name}"
                tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=name, kind="query", payload=payload))
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if not response:
            return VerificationResult(False, "LOW", {}, {})
        location = response.headers.get("Location") if hasattr(response, "headers") else None
        if response.status_code in (301, 302, 303, 307, 308) and location and testcase.payload in location:
            return VerificationResult(
                True,
                "MEDIUM",
                {"param": testcase.param, "location": location},
                {"param": testcase.param, "payload": testcase.payload},
                severity="LOW",
            )
        return VerificationResult(False, "LOW", {}, {})

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Open Redirect",
            severity="LOW",
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Validate redirect targets against an allowlist.",
            reproduction=vres.reproduction,
        )
