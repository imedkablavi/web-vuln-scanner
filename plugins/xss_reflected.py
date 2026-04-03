import random
import string
from typing import List, Dict
from html import unescape
from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding
from core.utils import logger


def _marker():
    return "XSS123_" + "".join(random.choices(string.ascii_letters, k=6))


class XSSReflectedPlugin(BasePlugin):
    name = "xss_reflected"
    supported_input_kinds = ["query", "body"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(surface.params or surface.inputs)

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        max_payloads = self.config.get("max_payloads", 6)
        tests: List[TestCase] = []
        targets = list(surface.params.keys()) + [i.name for i in surface.inputs]
        for name in targets[:max_payloads]:
            marker = _marker()
            payloads = [
                marker,
                f"'><script>window.__xss_marker='{marker}'</script>",
                f"\\\"{marker}\\\"",
            ]
            for p in payloads:
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind="query",
                        payload=p,
                    )
                )
                if len(tests) >= max_payloads:
                    break
            if len(tests) >= max_payloads:
                break
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if not response:
            return VerificationResult(False, "LOW", {}, {})
        body = unescape(response.text or "")
        marker = testcase.payload.replace("'><script>window.__xss_marker='", "").replace("'</script>", "").replace("\\\"", "").strip("'\"")
        if marker and marker in body:
            evidence = {"marker": marker, "param": testcase.param}
            confidence = "MEDIUM"
            return VerificationResult(True, confidence, evidence, {"param": testcase.param, "payload": testcase.payload}, severity="MEDIUM")
        return VerificationResult(False, "LOW", {}, {})

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Reflected XSS",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Encode untrusted data before rendering and use CSP.",
            reproduction=vres.reproduction,
        )
