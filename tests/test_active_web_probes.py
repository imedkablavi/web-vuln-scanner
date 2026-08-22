from __future__ import annotations

from dataclasses import dataclass, field

from layers.active_web_probes import ActiveWebProbeScanner


@dataclass
class Response:
    status_code: int = 200
    text: str = ""
    headers: dict = field(default_factory=dict)
    url: str = "https://example.test/search?q=base"


class Requester:
    def __init__(self):
        self.calls = []

    def send(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "TRACE":
            token = kwargs["headers"]["X-WVS-Trace-Canary"]
            return Response(text=f"X-WVS-Trace-Canary: {token}", url=url)

        params = kwargs.get("params") or []
        value = dict(params).get("q", "")
        if "X-WVS-Canary" in value:
            token = value.rsplit(": ", 1)[-1]
            return Response(headers={"X-WVS-Canary": token}, url=url)
        if "{{13*17}}" in value:
            return Response(text=value.replace("{{13*17}}", "221"), url=url)
        if "{{19*23}}" in value:
            return Response(text=value.replace("{{19*23}}", "437"), url=url)
        return Response(text="unchanged", url=url)


def config(*, max_requests=50):
    return {
        "active_checks": {
            "web": {
                "enabled": True,
                "max_urls": 3,
                "max_requests": max_requests,
                "ssti": True,
                "crlf": True,
                "trace": True,
            }
        }
    }


def test_active_web_probes_confirm_ssti_crlf_and_trace():
    requester = Requester()
    scanner = ActiveWebProbeScanner(requester, config())
    findings, meta = scanner.scan(
        [
            {
                "url": "https://example.test/search?q=base",
                "text": "baseline",
            }
        ]
    )

    finding_types = {finding.type for finding in findings}
    assert "Server-Side Template Injection" in finding_types
    assert "HTTP Response Header Injection" in finding_types
    assert "HTTP TRACE Enabled" in finding_types
    assert meta["requests_sent"] >= 4
    assert meta["max_requests"] == 50

    ssti = next(finding for finding in findings if finding.type == "Server-Side Template Injection")
    assert ssti.verification_status == "verified"
    assert ssti.confidence == "HIGH"
    assert ssti.reproducible is True


def test_trace_runs_once_per_origin():
    requester = Requester()
    scanner = ActiveWebProbeScanner(requester, config())
    scanner.scan(
        [
            {"url": "https://example.test/a", "text": "a"},
            {"url": "https://example.test/b", "text": "b"},
        ]
    )

    trace_calls = [call for call in requester.calls if call[0] == "TRACE"]
    assert len(trace_calls) == 1
    assert trace_calls[0][1] == "https://example.test/"


def test_request_budget_is_a_hard_cap():
    requester = Requester()
    scanner = ActiveWebProbeScanner(requester, config(max_requests=2))
    findings, meta = scanner.scan(
        [{"url": "https://example.test/search?q=base", "text": "baseline"}]
    )

    assert len(requester.calls) == 2
    assert meta["requests_sent"] == 2
    assert meta["max_requests"] == 2
    assert any("request budget" in item.lower() for item in meta["skipped"])
    assert {finding.type for finding in findings} <= {
        "HTTP TRACE Enabled",
        "HTTP Response Header Injection",
    }


def test_active_web_probes_skip_parameter_checks_without_query_string():
    requester = Requester()
    scanner = ActiveWebProbeScanner(requester, config())
    findings, meta = scanner.scan([{"url": "https://example.test/", "text": "baseline"}])

    assert [finding.type for finding in findings] == ["HTTP TRACE Enabled"]
    assert meta["checked_urls"] == 1


def test_active_web_probes_are_off_by_default():
    requester = Requester()
    scanner = ActiveWebProbeScanner(requester, {})
    findings, meta = scanner.scan([{"url": "https://example.test/search?q=base", "text": "baseline"}])

    assert findings == []
    assert meta["enabled"] is False
    assert requester.calls == []
