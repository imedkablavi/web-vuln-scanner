from __future__ import annotations

from dataclasses import dataclass, field

from layers.xml_checks import XMLParserProbeScanner


@dataclass
class Surface:
    url: str = "https://example.test/xml"
    method: str = "POST"
    source: str = "swagger"
    meta: dict = field(
        default_factory=lambda: {
            "request_content_types": ["application/xml"],
            "content_type": "application/xml",
        }
    )


@dataclass
class Response:
    status_code: int = 200
    text: str = ""


class APIEngine:
    def __init__(self, surfaces):
        self._surfaces = surfaces

    def get_endpoints(self):
        return list(self._surfaces)


class Requester:
    def __init__(self, expand=True):
        self.calls = []
        self.expand = expand

    def send(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        payload = kwargs.get("data", "")
        marker = payload.split('<!ENTITY wvs_probe "', 1)[1].split('"', 1)[0]
        if self.expand:
            return Response(text=f"<wvs><probe>{marker}</probe></wvs>")
        return Response(text=payload)


def enabled_config():
    return {"active_checks": {"xml": {"enabled": True, "max_requests": 2}}}


def test_internal_entity_expansion_is_detected_without_external_target():
    requester = Requester(expand=True)
    scanner = XMLParserProbeScanner(requester, enabled_config())
    findings, meta = scanner.scan(APIEngine([Surface()]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "XML DTD Entity Processing"
    assert finding.verification_status == "detected"
    assert finding.evidence["internal_entity_expanded"] is True
    sent = requester.calls[0][2]["data"]
    assert "http://" not in sent
    assert "https://" not in sent
    assert "file://" not in sent
    assert meta["requests_sent"] == 1


def test_echo_of_raw_xml_is_not_mistaken_for_entity_expansion():
    requester = Requester(expand=False)
    scanner = XMLParserProbeScanner(requester, enabled_config())
    findings, _meta = scanner.scan(APIEngine([Surface()]))
    assert findings == []


def test_xml_probe_is_disabled_by_default():
    requester = Requester()
    scanner = XMLParserProbeScanner(requester, {})
    findings, meta = scanner.scan(APIEngine([Surface()]))
    assert findings == []
    assert requester.calls == []
    assert meta["enabled"] is False
