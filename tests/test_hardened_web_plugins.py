from __future__ import annotations

from dataclasses import dataclass, field

from core.models import AttackSurface
from plugins.open_redirect import OpenRedirectPlugin
from plugins.xss_reflected import XSSReflectedPlugin


@dataclass
class Response:
    status_code: int = 200
    text: str = ""
    headers: dict = field(default_factory=dict)
    url: str = "https://example.test/"


def surface(url="https://example.test/search?q=hello"):
    return AttackSurface(
        url=url,
        method="GET",
        params={"q": "hello", "next": "/home"},
        inputs=[],
        source="fixture",
    )


def test_reflected_markup_requires_parsed_injected_element():
    plugin = XSSReflectedPlugin(None, {"enabled": True, "max_tests_per_surface": 2})
    target = surface()
    testcase = plugin.generate_tests(target, {})[0]
    marker = testcase.notes.split(":", 1)[1]

    encoded = Response(
        text=f"<html><body>&lt;wvs-probe data-wvs=&quot;{marker}&quot;&gt;&lt;/wvs-probe&gt;</body></html>",
        headers={"Content-Type": "text/html"},
    )
    result = plugin.verify(testcase, {"text": "baseline"}, encoded, {})
    assert result.is_verified is False

    injected = Response(
        text=f'<html><body><wvs-probe data-wvs="{marker}"></wvs-probe></body></html>',
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    result = plugin.verify(testcase, {"text": "baseline"}, injected, {})
    assert result.is_verified is True
    assert result.verification_status == "detected"
    assert result.evidence["context"] == "html-markup"

    finding = plugin.build_finding(testcase, result, target)
    assert finding.type == "Reflected HTML Injection"
    assert finding.reproducible is True


def test_open_redirect_requires_exact_reserved_canary_destination():
    plugin = OpenRedirectPlugin(None, {"enabled": True})
    target = surface("https://example.test/login?next=/dashboard")
    testcase = plugin.generate_tests(target, {})[0]

    safe_response = Response(
        status_code=302,
        headers={"Location": "/dashboard"},
        url=target.url,
    )
    safe_result = plugin.verify(testcase, {"headers": {}}, safe_response, {})
    assert safe_result.is_verified is False

    vulnerable_response = Response(
        status_code=302,
        headers={"Location": testcase.payload},
        url=target.url,
    )
    vulnerable_result = plugin.verify(testcase, {"headers": {}}, vulnerable_response, {})
    assert vulnerable_result.is_verified is True
    assert vulnerable_result.verification_status == "verified"
    assert vulnerable_result.evidence["destination_host"] == "wvs.invalid"

    finding = plugin.build_finding(testcase, vulnerable_result, target)
    assert finding.severity == "MEDIUM"
    assert finding.reproducible is True
