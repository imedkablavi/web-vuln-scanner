from __future__ import annotations

import secrets
from html.parser import HTMLParser
from typing import Dict, List

from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding


class _MarkerParser(HTMLParser):
    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.injected_element = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "wvs-xss":
            return
        attributes = {str(key).lower(): str(value or "") for key, value in attrs}
        if attributes.get("data-wvs") == self.marker:
            self.injected_element = True


def _marker() -> str:
    return f"WVSXSS_{secrets.token_hex(6)}"


class XSSReflectedPlugin(BasePlugin):
    """Detect unescaped reflected HTML using a non-executable custom element.

    This intentionally does not execute JavaScript. A finding means the response
    parsed attacker-controlled markup as an HTML element, which is strong XSS
    sink evidence but still remains a `detected` result rather than `verified`
    script execution.
    """

    name = "xss_reflected"
    supported_input_kinds = ["query", "body"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(surface.params or any(item.kind in self.supported_input_kinds for item in surface.inputs))

    def _targets(self, surface: AttackSurface):
        targets = [(name, "query") for name in surface.params]
        targets.extend(
            (item.name, item.kind)
            for item in surface.inputs
            if item.kind in self.supported_input_kinds
        )
        deduped = []
        seen = set()
        for target in targets:
            if target not in seen:
                seen.add(target)
                deduped.append(target)
        return deduped

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        max_params = max(1, min(10, int(self.config.get("max_params", 3))))
        tests: List[TestCase] = []
        for name, kind in self._targets(surface)[:max_params]:
            marker = _marker()
            payload = f'<wvs-xss data-wvs="{marker}">{marker}</wvs-xss>'
            tests.append(
                TestCase(
                    plugin=self.name,
                    surface_id=surface.id,
                    param=name,
                    kind=kind,
                    payload=payload,
                    baseline_key=f"{surface.id}:{name}",
                    notes=f"marker={marker}",
                )
            )
        return tests

    @staticmethod
    def _marker_from_payload(payload: str) -> str:
        prefix = 'data-wvs="'
        if prefix not in payload:
            return ""
        return payload.split(prefix, 1)[1].split('"', 1)[0]

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None or baseline is None:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "missing_baseline_or_response"},
                {},
                verification_status="not_reproducible",
            )

        marker = self._marker_from_payload(testcase.payload)
        if not marker or marker in (baseline.get("text") or ""):
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        content_type = str(getattr(response, "headers", {}).get("Content-Type", "")).lower()
        if "html" not in content_type:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        body = response.text or ""
        parser = _MarkerParser(marker)
        try:
            parser.feed(body)
        except Exception:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        if not parser.injected_element:
            return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

        return VerificationResult(
            True,
            "HIGH",
            {
                "param": testcase.param,
                "signal": "attacker_markup_parsed_as_html",
                "marker": marker,
                "content_type": content_type.split(";", 1)[0],
                "status": response.status_code,
                "baseline_status": baseline.get("status"),
            },
            {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
            severity="MEDIUM",
            verification_status="detected",
            rationale=(
                "A non-executable attacker-controlled custom element was reflected unescaped and parsed as HTML. "
                "This is strong reflected-XSS sink evidence, but JavaScript execution was not attempted."
            ),
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="Reflected XSS",
            title="Reflected HTML Injection / XSS Candidate",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Apply context-aware output encoding and a restrictive Content Security Policy.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=False,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
