from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.models import AttackSurface
from core.request_manager import RequestManager
from core.scanner import PluginRegistry, ScannerEngine
from layers.cors_verification import CORSVerifier
from layers.graphql_verification import GraphQLVerifier
from plugins.crlf_injection import CRLFInjectionPlugin
from plugins.host_header import HostHeaderPlugin
from plugins.ssrf import SSRFPlugin
from plugins.ssti import SSTIPlugin
from tests.corpus.additional_vuln_server import AdditionalVulnHandler


SSRF_PROOF = "ssrf-callback-proof-marker"


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
        "active_verification": {
            "cors": {"enabled": True, "max_urls": 5},
            "graphql": {"enabled": True, "max_requests": 2},
        },
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


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: N802
        return

    def do_GET(self):  # noqa: N802
        data = SSRF_PROOF.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def ssrf_callback():
    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/proof"
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

    assert any(finding.plugin == "ssti" and finding.verification_status == "verified" for finding in vulnerable_findings)
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

    assert any(finding.plugin == "crlf_injection" and finding.verification_status == "verified" for finding in vulnerable_findings)
    assert not any(finding.plugin == "crlf_injection" for finding in safe_findings)


def test_ssrf_requires_callback_proof_and_avoids_safe_fixture(additional_corpus, ssrf_callback):
    engine = _engine_with(
        SSRFPlugin,
        {
            "max_tests_per_surface": 1,
            "request_budget": 1,
            "callback_url": ssrf_callback,
            "expected_marker": SSRF_PROOF,
            "allow_external_callback": False,
        },
    )
    vulnerable = AttackSurface(
        url=f"{additional_corpus}/ssrf",
        method="GET",
        params={"url": "https://example.invalid/blocked"},
        source="local-regression-corpus",
    )
    safe = AttackSurface(
        url=f"{additional_corpus}/ssrf-safe",
        method="GET",
        params={"url": "https://example.invalid/blocked"},
        source="local-regression-corpus",
    )

    vulnerable_findings = engine.scan([vulnerable])
    safe_findings = engine.scan([safe])

    assert any(finding.plugin == "ssrf" and finding.verification_status == "verified" for finding in vulnerable_findings)
    assert not any(finding.plugin == "ssrf" for finding in safe_findings)


def test_host_header_requires_security_sensitive_url_influence(additional_corpus):
    engine = _engine_with(HostHeaderPlugin, {"max_tests_per_surface": 1, "request_budget": 1})
    vulnerable = AttackSurface(
        url=f"{additional_corpus}/host-header",
        method="GET",
        params={},
        source="local-regression-corpus",
    )
    safe = AttackSurface(
        url=f"{additional_corpus}/host-header-safe",
        method="GET",
        params={},
        source="local-regression-corpus",
    )

    vulnerable_findings = engine.scan([vulnerable])
    safe_findings = engine.scan([safe])

    assert any(finding.plugin == "host_header" and finding.verification_status == "verified" for finding in vulnerable_findings)
    assert not any(finding.plugin == "host_header" for finding in safe_findings)


def test_cors_two_origin_positive_and_negative_local_fixtures(additional_corpus):
    requester = RequestManager(make_config())
    verifier = CORSVerifier(requester, make_config())

    vulnerable_findings, _ = verifier.scan([f"{additional_corpus}/cors-vuln"])
    safe_findings, _ = CORSVerifier(requester, make_config()).scan([f"{additional_corpus}/cors-safe"])

    assert any(finding.plugin == "cors_verification" and finding.verification_status == "verified" for finding in vulnerable_findings)
    assert not any(finding.plugin == "cors_verification" for finding in safe_findings)


def test_graphql_verbose_error_positive_and_negative_local_fixtures(additional_corpus):
    requester = RequestManager(make_config())
    vulnerable_findings, vulnerable_meta = GraphQLVerifier(requester, make_config()).scan(f"{additional_corpus}/graphql-vuln")
    safe_findings, safe_meta = GraphQLVerifier(requester, make_config()).scan(f"{additional_corpus}/graphql-safe")

    assert vulnerable_meta["observations"]["introspection"]["enabled"] is True
    assert safe_meta["observations"]["introspection"]["enabled"] is False
    assert any(finding.plugin == "graphql_verification" and finding.verification_status == "verified" for finding in vulnerable_findings)
    assert not any(finding.plugin == "graphql_verification" for finding in safe_findings)


def test_new_experimental_plugins_remain_registry_blocked():
    config = make_config()
    config["plugins"] = {
        "ssrf": {"enabled": True, "callback_url": "http://127.0.0.1:9/proof", "expected_marker": SSRF_PROOF},
        "host_header": {"enabled": True},
    }
    loaded = PluginRegistry.load_plugins(config, RequestManager(config))
    assert not ({"ssrf", "host_header"} & {plugin.name for plugin in loaded})


def test_additional_detectors_are_bounded_and_non_destructive():
    ssti = SSTIPlugin(None, {"max_tests_per_surface": 99, "request_budget": 99})
    crlf = CRLFInjectionPlugin(None, {"max_tests_per_surface": 99, "request_budget": 99})
    ssrf = SSRFPlugin(
        None,
        {
            "max_tests_per_surface": 99,
            "request_budget": 99,
            "callback_url": "http://127.0.0.1:8123/proof",
            "expected_marker": SSRF_PROOF,
        },
    )
    host = HostHeaderPlugin(None, {"max_tests_per_surface": 99, "request_budget": 99})

    assert ssti.request_budget(ssti.config) <= 2
    assert crlf.request_budget(crlf.config) <= 2
    assert ssrf.request_budget(ssrf.config) <= 1
    assert host.request_budget(host.config) <= 1
    assert "{{1337*17}}" in ssti.payload
    assert all(token not in ssti.payload.lower() for token in ("exec", "system", "popen", "file://"))
    assert "X-Scanner-Canary" in crlf.payload
    assert all(token not in crlf.payload.lower() for token in ("set-cookie", "location:", "javascript:"))
    assert ssrf._callback_allowed() is True
    assert SSRFPlugin(None, {"callback_url": "http://169.254.169.254/latest", "expected_marker": "x"})._callback_allowed() is False
    assert SSRFPlugin(None, {"callback_url": "http://10.0.0.1/internal", "expected_marker": "x"})._callback_allowed() is False
    assert host._canary_host().endswith(".invalid")
