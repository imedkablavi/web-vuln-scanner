from __future__ import annotations

import random
import string
from typing import List, Dict

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


def _token():
    return "CMD_" + "".join(random.choices(string.ascii_uppercase, k=6))


class CMDInjectionPlugin(BasePlugin):
    name = "cmd_injection"
    supported_input_kinds = ["query", "body"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface, context=None):
        return bool(surface.params or surface.inputs)

    def generate_tests(self, surface, context: Dict) -> List[TestCase]:
        tests = []
        for name in list(surface.params.keys())[:3]:
            tok = _token()
            for payload in [f"; echo {tok}", f"| echo {tok}", f"&& echo {tok}"]:
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind="query",
                        payload=payload,
                    )
                )
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if not response:
            return VerificationResult(False, "LOW", {}, {})
        token = testcase.payload.split()[-1]
        if token in response.text:
            return VerificationResult(
                True,
                "MEDIUM",
                {"param": testcase.param, "token": token},
                {"param": testcase.param, "payload": testcase.payload},
                severity="HIGH",
            )
        return VerificationResult(False, "LOW", {}, {})

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Command Injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Avoid shell invocation; use safe APIs and proper validation.",
            reproduction=vres.reproduction,
        )
