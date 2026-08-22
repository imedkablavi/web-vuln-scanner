from __future__ import annotations

import hashlib
from typing import Dict, List

from bs4 import BeautifulSoup

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


class XSSReflectedPlugin(BasePlugin):
    name = "xss_reflected"
    supported_input_kinds = ["query", "body"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def max_tests_per_surface(self, config: Dict) -> int:
        return max(1, int(config.get("max_tests_per_surface", 4)))

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(surface.params or any(item.kind in self.supported_input_kinds for item in surface.inputs))

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        targets = [(name, "query") for name in surface.params]
        targets.extend((item.name, item.kind) for item in surface.inputs if item.kind in self.supported_input_kinds)
        tests: List[TestCase] = []
        for name, kind in targets:
            marker = hashlib.sha256(f"{surface.id}:{name}:{kind}".encode("utf-8")).hexdigest()[:12]
            element = f'<wvs-probe data-wvs="{marker}"></wvs-probe>'
            for payload in (element, f'\">{element}'):
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind=kind,
                        payload=payload,
                        notes=f"markup-canary:{marker}",
                    )
                )
                if len(tests) >= self.max_tests_per_surface(self.config):
                    return tests
        return tests

    @staticmethod
    def _marker(testcase: TestCase) -> str:
        prefix = "markup-canary:"
        if testcase.notes and testcase.notes.startswith(prefix):
            return testcase.notes[len(prefix):]
        return ""

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        marker = self._marker(testcase)
        if not marker:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        content_type = str(response.headers.get("Content-Type") or "").lower() if hasattr(response, "headers") else ""
        body = response.text or ""
        if "html" not in content_type and "<html" not in body.lower():
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        soup = BeautifulSoup(body, "html.parser")
        injected = soup.find("wvs-probe", attrs={"data-wvs": marker})
        if injected is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        baseline_text = str((baseline or {}).get("text") or "") if isinstance(baseline, dict) else ""
        if marker in baseline_text:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "parameter": testcase.param,
                "marker": marker,
                "status": response.status_code,
                "parsed_element": "wvs-probe",
                "context": "html-markup",
            },
            {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
            severity="MEDIUM",
            verification_status="detected",
            rationale="The response parser reconstructed the injected canary as an HTML element. Script execution was not attempted or claimed.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Reflected HTML Injection",
            title="Reflected Markup Injection Confirmed",
            category="xss",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Encode untrusted values for the exact HTML context before rendering them. Add CSP as defense in depth, not as the primary fix.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="safe-active-web",
            reproducible=True,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
