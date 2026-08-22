from __future__ import annotations

import hashlib
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from core.models import AttackSurface, Finding
from .base import BasePlugin, TestCase, VerificationResult


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
        "callback",
        "dest",
        "destination",
        "goto",
    }

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def max_tests_per_surface(self, config: Dict) -> int:
        return max(1, int(config.get("max_tests_per_surface", 2)))

    def applicable(self, surface: AttackSurface) -> bool:
        return any(str(name).lower() in self.candidate_params for name in surface.params)

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        tests: List[TestCase] = []
        for name in surface.params:
            if str(name).lower() not in self.candidate_params:
                continue
            token = hashlib.sha256(f"{surface.id}:{name}".encode("utf-8")).hexdigest()[:12]
            payload = f"https://wvs.invalid/redirect-check/{token}"
            tests.append(
                TestCase(
                    plugin=self.name,
                    surface_id=surface.id,
                    param=name,
                    kind="query",
                    payload=payload,
                    notes="reserved-host redirect canary",
                )
            )
        return tests[: self.max_tests_per_surface(self.config)]

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None or not hasattr(response, "headers"):
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")
        if response.status_code not in {301, 302, 303, 307, 308}:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        location = str(response.headers.get("Location") or "").strip()
        if not location:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        resolved = urljoin(getattr(response, "url", "") or "https://target.invalid/", location)
        parsed = urlparse(resolved)
        expected = urlparse(testcase.payload)
        baseline_location = ""
        if isinstance(baseline, dict):
            baseline_location = str((baseline.get("headers") or {}).get("Location") or "")

        verified = (
            parsed.scheme == "https"
            and (parsed.hostname or "").lower() == "wvs.invalid"
            and parsed.path == expected.path
            and testcase.payload != baseline_location
        )
        if not verified:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "parameter": testcase.param,
                "status": response.status_code,
                "location": location,
                "resolved_location": resolved,
                "destination_host": parsed.hostname,
            },
            {"param": testcase.param, "payload": testcase.payload},
            severity="MEDIUM",
            verification_status="verified",
            rationale="The application redirected directly to the reserved canary host supplied through the tested parameter.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Open Redirect",
            title="User-Controlled Redirect Confirmed",
            category="redirect",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Resolve redirect targets server-side against an explicit allowlist or use internal route identifiers instead of accepting arbitrary URLs.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="safe-active-web",
            reproducible=True,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
