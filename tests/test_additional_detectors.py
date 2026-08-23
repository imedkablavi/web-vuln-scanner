from __future__ import annotations

import threading
from http.server import HTTPServer

import pytest

from core.models import AttackSurface
from core.request_manager import RequestManager
from core.scanner import ScannerEngine
from plugins.crlf_injection import CRLFInjectionPlugin
from plugins.ssti import SSTIPlugin
from tests.corpus.additional_vuln_server import AdditionalVulnHandler


def make_config():
    return {
        "scope": {"include_domains": [], "allow_private": True},
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 1,
            "threads": 1,
            "per_host_concurrency": 1,
            "global_timeout_seconds": 5,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
        "plugin_contract": "v2",
        "verified_only": False,
        "max_findings_per_plugin": 10,
        "plugins": {},
    }


@pytest.fixture()
def additional_corpus():
    server = HTTPServer(("127.0.0.1", 0), AdditionalVulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _engine_with(plugin_cls, plugin_config=None):
    config = make_config()
    requester = RequestManager(config)
    engine = ScannerEngine(requester, config)
    engine.plugins = [
        plugin_cls(
            requester,
            {
                "enabled": True,
                "max_tests_per_surface": 2,
                "request_budget": 2,
                "timeout_seconds": 0.5,
                **(plugin_config or {}),
            },
        )
    ]
    return engine


def test_ssti_positive_and_negative_local_fixtures(additional_corpus):
    engine = _engine_with(SSTIPlugin)
    vulnerable = AttackSurface(
        url=f"{additional_corpus}/ssti",
        method="GET",
        params={"template": "hello"},
        source="local-regression-corpus",
    )
    safe = AttackSurface(
        url=f"{additional_corpus}/ssti-safe",
        method="GET",
        params={"template": "hello"},
        source="local-regression-corpus",
    )

    vulnerable_findings = engine.scan([vulnerable])
    safe_findings = engine.scan([safe])

    assert any(
        finding.plugin == "ssti" and finding.verification_status == "verified"
        for finding in vulnerable_findings
    )
    assert not any(finding.plugin == "ssti" for finding in safe_findings)


def test_crlf_positive_and_negative_local_fixtures(additional_corpus):
    engine = _engine_with(CRLFInjectionPlugin)
    vulnerable = AttackSurface(
        url=f"{additional_corpus}/crlf",
        method="GET",
        params={"next": "/home"},
        source="local-regression-corpus",
    )
    safe = AttackSurface(
        url=f"{additional_corpus}/crlf-safe",
        method="GET",
        params={"next": "/home"},
        source="local-regression-corpus",
    )

    vulnerable_findings = engine.scan([vulnerable])
    safe_findings = engine.scan([safe])

    assert any(
        finding.plugin == "crlf_injection" and finding.verification_status == "verified"
        for finding in vulnerable_findings
    )
    assert not any(finding.plugin == "crlf_injection" for finding in safe_findings)


def test_additional_detectors_are_bounded_and_non_destructive():
    ssti = SSTIPlugin(None, {"max_tests_per_surface": 99, "request_budget": 99})
    crlf = CRLFInjectionPlugin(None, {"max_tests_per_surface": 99, "request_budget": 99})
    assert ssti.request_budget(ssti.config) <= 2
    assert crlf.request_budget(crlf.config) <= 2
    assert "{{1337*17}}" in ssti.payload
    assert all(token not in ssti.payload.lower() for token in ("exec", "system", "popen", "file://"))
    assert "X-Scanner-Canary" in crlf.payload
    assert all(token not in crlf.payload.lower() for token in ("set-cookie", "location:", "javascript:"))
