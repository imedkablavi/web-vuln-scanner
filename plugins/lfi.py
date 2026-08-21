from __future__ import annotations

import random
import string
from typing import List, Dict

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding
from core.utils import get_content_hash


class LFIPlugin(BasePlugin):
    name = "lfi"
    supported_input_kinds = ["query", "body", "path"]
    patterns = ["root:x:0:0:", "[extensions]", "[fonts]"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface, context=None):
        return bool(surface.params or surface.inputs)

    def generate_tests(self, surface, context: Dict) -> List[TestCase]:
        payloads = ["../../../../etc/passwd", "..\\..\\..\\Windows\\win.ini"]
        tests = []
        for name in list(surface.params.keys())[:3]:
            for p in payloads:
                tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=name, kind="query", payload=p))
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if not response or not baseline:
            return VerificationResult(False, "LOW", {}, {})
        text = response.text or ""
        status_ok = response.status_code == 200
        pattern_hit = any(pat in text for pat in self.patterns)
        current_hash = get_content_hash(text)
        delta = baseline["hash"] != current_hash
        signals = [pattern_hit, status_ok, delta]
        if sum(1 for s in signals if s) >= 2:
            return VerificationResult(
                True,
                "MEDIUM",
                {"param": testcase.param, "payload": testcase.payload, "pattern": pattern_hit, "delta": delta},
                {"param": testcase.param, "payload": testcase.payload},
                severity="HIGH",
            )
        return VerificationResult(False, "LOW", {}, {})

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Local File Inclusion",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Sanitize file path parameters and disallow path traversal.",
            reproduction=vres.reproduction,
        )
