from __future__ import annotations

import secrets
from typing import Dict, List
from urllib.parse import urlparse

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


class OpenRedirectPlugin(BasePlugin):
    name = "open_redirect"
    supported_input_kinds = ["query"]
    candidate_params = {
        "next",
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_to",
        "returnurl",
        "continue",
        "dest",
        "destination",
        "callback",
        "go",
        "to",
        "out",
    }

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def _targets(self, surface: AttackSurface):
        return [name for name in surface.params if name.lower() in self.candidate_params]

    def applicable(self, surface: AttackSurface, context=None):
        return bool(self._targets(surface))

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        max_params = max(1, min(10, int(self.config.get("max_params", 4))))
        tests: List[TestCase] = []
        for name in self._targets(surface)[:max_params]:
            marker = secrets.token_hex(6)
            payload = f"https://redirect.invalid/wvs-{marker}"
            tests.append(
                TestCase(
                    plugin=self.name,
                    surface_id=surface.id,
                    param=name,
                    kind="query",
                    payload=payload,
                    baseline_key=f"{surface.id}:{name}",
                    notes="External .invalid redirect target; redirects must not be followed by the requester.",
                )
            )
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        location = str(getattr(response, "headers", {}).get("Location", "") or "").strip()
        if int(response.status_code) not in {301, 302, 303, 307, 308} or not location:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        parsed = urlparse(location)
        payload = urlparse(testcase.payload)
        external_match = (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname == payload.hostname == "redirect.invalid"
            and parsed.path == payload.path
        )
        if not external_match:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        baseline_location = ""
        if baseline:
            baseline_location = str((baseline.get("headers") or {}).get("Location", "") or "")
        if baseline_location == location:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "signal": "external_location_header",
                "location_host": parsed.hostname,
                "location_path": parsed.path,
                "status": response.status_code,
                "baseline_location": baseline_location,
                "redirect_followed": False,
            },
            {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
            severity="MEDIUM",
            verification_status="verified",
            rationale=(
                "The server returned an HTTP redirect to the exact external .invalid marker target. "
                "The scanner does not need to follow the redirect to verify the issue."
            ),
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Open Redirect",
            title="Unvalidated External Redirect",
            category="redirect",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Allow only relative redirects or validate destinations against a strict origin allowlist.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=True,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
