from __future__ import annotations

import re
import secrets
from typing import Dict, List

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


class CMDInjectionPlugin(BasePlugin):
    name = "cmd_injection"
    supported_input_kinds = ["query", "body"]
    default_candidate_param_regex = r"(?i)(cmd|command|exec|host|hostname|ip|ping|lookup|target|query|name)"

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
        if not bool(self.config.get("allow_command_probe", False)):
            return []
        max_params = max(1, min(3, int(self.config.get("max_params", 1))))
        separators = list(self.config.get("separators", [";", "&&"]))[:2]
        tests: List[TestCase] = []
        for name, kind in self._targets(surface)[:max_params]:
            token = f"WVS_CMD_{secrets.token_hex(5)}"
            for separator in separators:
                payload = f"{separator} echo {token}"
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=name,
                        kind=kind,
                        payload=payload,
                        baseline_key=f"{surface.id}:{name}",
                        notes="Bounded non-destructive echo marker. No persistence, file writes, or outbound callbacks.",
                    )
                )
        return tests

    @staticmethod
    def _token(payload: str) -> str:
        match = re.search(r"\bWVS_CMD_[0-9a-f]{10}\b", payload or "")
        return match.group(0) if match else ""

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None or baseline is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        token = self._token(testcase.payload)
        if not token or token in (baseline.get("text") or ""):
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        body = response.text or ""
        if token not in body:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "signal": "command_output_marker",
                "token": token,
                "status": response.status_code,
                "baseline_status": baseline.get("status"),
            },
            {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
            severity="HIGH",
            verification_status="detected",
            rationale=(
                "A unique echo marker appeared in the response only after a shell-separator probe. "
                "The probe is intentionally non-destructive and remains experimental."
            ),
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Command Injection",
            title="OS Command Injection Signal",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Avoid shell invocation with untrusted input; use direct process APIs with fixed argument vectors and strict validation.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=False,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
