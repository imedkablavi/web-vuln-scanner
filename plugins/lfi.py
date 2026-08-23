from __future__ import annotations

import re
from typing import Dict, List

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


class LFIPlugin(BasePlugin):
    name = "lfi"
    supported_input_kinds = ["query", "body"]
    default_candidate_param_regex = r"(?i)(file|path|page|template|include|document|folder|dir|view)"
    signatures = (
        ("unix_passwd", re.compile(r"(?m)^root:[^:\r\n]*:0:0:")),
        ("windows_win_ini", re.compile(r"(?im)^\s*\[(extensions|fonts)\]\s*$")),
    )

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def _candidate(self, name: str) -> bool:
        pattern = str(self.config.get("candidate_param_regex", self.default_candidate_param_regex))
        try:
            return bool(re.search(pattern, name or ""))
        except re.error:
            return bool(re.search(self.default_candidate_param_regex, name or ""))

    def _targets(self, surface: AttackSurface):
        targets = [(name, "query") for name in surface.params if self._candidate(name)]
        targets.extend(
            (item.name, item.kind)
            for item in surface.inputs
            if item.kind in self.supported_input_kinds and self._candidate(item.name)
        )
        deduped = []
        seen = set()
        for target in targets:
            if target not in seen:
                seen.add(target)
                deduped.append(target)
        return deduped

    def applicable(self, surface: AttackSurface, context=None):
        return bool(self._targets(surface))

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        payloads = [
            ("unix", "../../../../etc/passwd"),
            ("windows", "..\\..\\..\\..\\Windows\\win.ini"),
        ]
        max_params = max(1, min(5, int(self.config.get("max_params", 2))))
        tests: List[TestCase] = []
        for name, kind in self._targets(surface)[:max_params]:
            for family, payload in payloads:
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind=kind,
                        payload=payload,
                        baseline_key=f"{surface.id}:{name}",
                        notes=f"path_family={family}",
                    )
                )
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None or baseline is None:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "missing_baseline_or_response"},
                {},
                verification_status="not_reproducible",
            )

        text = response.text or ""
        baseline_text = baseline.get("text") or ""
        for signature_name, pattern in self.signatures:
            candidate_match = pattern.search(text)
            baseline_match = pattern.search(baseline_text)
            if candidate_match and not baseline_match and 200 <= int(response.status_code) < 300:
                return VerificationResult(
                    True,
                    "HIGH",
                    {
                        "param": testcase.param,
                        "signal": "file_signature_after_traversal_probe",
                        "signature": signature_name,
                        "status": response.status_code,
                        "baseline_status": baseline.get("status"),
                    },
                    {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
                    severity="HIGH",
                    verification_status="detected",
                    rationale=(
                        "A known operating-system file signature appeared only after a bounded traversal probe. "
                        "The report stores the signature name rather than copying file contents."
                    ),
                )

        return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Path Traversal / Local File Inclusion",
            title="Path Traversal / LFI Signal",
            category="file-access",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Resolve paths against a fixed base directory, reject traversal segments, and avoid user-controlled include paths.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=False,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
