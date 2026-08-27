from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer
from types import SimpleNamespace

import pytest

from core.models import AttackSurface, Finding
from core.reporter import Reporter
from core.request_manager import RequestManager
from core.scanner import PluginRegistry, ScannerEngine
from layers.data_exposure import DataExposureScanner
from plugins.base import BasePlugin, PluginContractError, TestCase, VerificationResult
from smoke.mock_server import MockHandler


def make_config(*, allow_private=False, include_domains=None, max_retries=0, per_host=1):
    return {
        "scope": {
            "include_domains": [] if include_domains is None else include_domains,
            "allow_private": allow_private,
        },
        "concurrency": {
            "delay": 0,
            "max_retries": max_retries,
            "timeout": 1,
            "threads": 2,
            "per_host_concurrency": per_host,
            "global_timeout_seconds": 5,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": max_retries,
            "follow_redirects": False,
        },
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
        "plugin_contract": "v2",
        "verified_only": False,
        "max_findings_per_plugin": 10,
        "plugins": {
            "sqli": {
                "enabled": True,
                "max_tests_per_surface": 1,
                "request_budget": 1,
                "timeout_seconds": 0.5,
                "min_length_delta_ratio": 0.05,
            },
            "business_logic": {"enabled": False},
            "xss_reflected": {"enabled": False},
            "lfi": {"enabled": False},
            "cmd_injection": {"enabled": False},
            "open_redirect": {"enabled": False},
            "ssti": {"enabled": False},
            "crlf_injection": {"enabled": False},
        },
    }


@pytest.fixture()
def local_corpus():
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    server.session_store = {}
    server.access_tokens = {}
    server.refresh_tokens = {}
    server.document_store = {}
    server.next_document_id = 100
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_local_corpus_detects_known_sqli_and_avoids_known_safe_query(local_corpus):
    config = make_config(allow_private=True)
    requester = RequestManager(config)
    engine = ScannerEngine(requester, config)

    vulnerable = AttackSurface(url=f"{local_corpus}/sqli", method="GET", params={"id": "1"}, source="regression-corpus")
    safe = AttackSurface(url=f"{local_corpus}/clean", method="GET", params={"id": "1"}, source="regression-corpus")

    vulnerable_findings = engine.scan([vulnerable])
    safe_findings = engine.scan([safe])

    assert any(f.plugin == "sqli" and f.verification_status in {"detected", "verified"} for f in vulnerable_findings)
    assert not any(f.plugin == "sqli" for f in safe_findings)


def test_authenticated_cookie_session_isolated_from_unauthenticated_request(local_corpus):
    requester = RequestManager(make_config(allow_private=True))
    unauthenticated = requester.send("GET", f"{local_corpus}/dashboard")
    authenticated = requester.send(
        "GET",
        f"{local_corpus}/dashboard",
        cookies={"session": "LOW_USER_SESSION"},
    )
    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200
    assert "low_user" in authenticated.text


def test_scope_guard_blocks_loopback_without_explicit_local_permission(monkeypatch):
    requester = RequestManager(make_config(allow_private=False, include_domains=[]))
    called = False

    def fake_request(**kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(requester.session, "request", fake_request)
    with pytest.raises(RuntimeError, match="not allowed by scope"):
        requester.send("GET", "http://127.0.0.1:8123/")
    assert called is False


def test_experimental_plugins_cannot_be_enabled_by_config():
    config = make_config()
    for name in PluginRegistry.experimental:
        config["plugins"][name]["enabled"] = True
    loaded = PluginRegistry.load_plugins(config, RequestManager(config))
    loaded_names = {plugin.name for plugin in loaded}
    assert not (PluginRegistry.experimental & loaded_names)


class DummyPlugin(BasePlugin):
    name = "dummy"
    supported_input_kinds = ["query"]

    @classmethod
    def enabled(cls, config):
        return True

    def applicable(self, surface):
        return True

    def generate_tests(self, surface, context):
        return [
            TestCase(plugin=self.name, surface_id=surface.id, param="id", kind="query", payload=str(index))
            for index in range(10)
        ]

    def verify(self, testcase, baseline, response, context):
        return VerificationResult(False, "LOW", {"reason": "fixture"}, {}, verification_status="not_reproducible")

    def build_finding(self, testcase, vres, surface):
        raise AssertionError("fixture never reports a finding")


def test_plugin_request_budget_and_timeout_are_enforced(monkeypatch):
    config = make_config(allow_private=False, include_domains=[])
    config["plugins"] = {}
    requester = RequestManager(config)
    observed_timeouts = []

    def fake_request(**kwargs):
        observed_timeouts.append(kwargs["timeout"])
        return SimpleNamespace(status_code=200, headers={}, text="constant", url=kwargs["url"])

    monkeypatch.setattr(requester.session, "request", fake_request)
    engine = ScannerEngine(requester, config)
    engine.plugins = [DummyPlugin(requester, {"max_tests_per_surface": 8, "request_budget": 2, "timeout_seconds": 0.25})]
    surface = AttackSurface(url="https://public.example/test", method="GET", params={"id": "1"}, source="unit")

    findings = engine.scan([surface])

    assert findings == []
    assert len(observed_timeouts) == 3  # one baseline + two budgeted plugin requests
    assert observed_timeouts[1:] == [0.25, 0.25]
    stats = engine.last_run_stats["plugin_details"]["dummy"]
    assert stats["executed_requests"] == 2
    assert stats["request_budget"] == 2


def test_plugin_contract_rejects_reportable_result_without_evidence_or_reproduction():
    plugin = DummyPlugin(None, {})
    with pytest.raises(PluginContractError, match="no evidence"):
        plugin.validate_verification_result(
            VerificationResult(True, "HIGH", {}, {"param": "id"}, verification_status="verified")
        )
    with pytest.raises(PluginContractError, match="no reproduction"):
        plugin.validate_verification_result(
            VerificationResult(True, "HIGH", {"signal": "fixture"}, {}, verification_status="verified")
        )


def test_per_host_concurrency_limit_is_respected(monkeypatch):
    requester = RequestManager(make_config(per_host=1))
    state_lock = threading.Lock()
    active = 0
    max_active = 0

    def fake_request(**kwargs):
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.02)
        with state_lock:
            active -= 1
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(requester.session, "request", fake_request)
    threads = [threading.Thread(target=requester.send, args=("GET", "https://public.example/resource")) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert max_active == 1


def test_rate_limit_retry_is_bounded(monkeypatch):
    requester = RequestManager(make_config(max_retries=1))
    calls = 0

    def fake_request(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return SimpleNamespace(status_code=429, headers={"Retry-After": "0"}, text="limited", url=kwargs["url"])
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(requester.session, "request", fake_request)
    response = requester.send("GET", "https://public.example/rate")
    assert response.status_code == 200
    assert calls == 2


def test_data_exposure_evidence_redacts_secret_values():
    scanner = DataExposureScanner(
        requester=None,
        config={"passive_checks": {"data_exposure": {"enabled": True}}},
    )
    snapshot = {
        "url": "https://example.test/.env.bak",
        "status": 200,
        "headers": {},
        "content_type": "text/plain",
        "text": "APP_ENV=dev\nDB_PASSWORD=super-secret\nAPI_KEY=mock-debug-key",
        "path": "/.env.bak",
    }
    findings = scanner._check_exposed_files(snapshot) + scanner._check_sensitive_indicators(snapshot)
    serialized = json.dumps([finding.evidence for finding in findings])
    assert "super-secret" not in serialized
    assert "mock-debug-key" not in serialized
    assert "***redacted***" in serialized


def test_json_and_html_reports_redact_sensitive_keys(tmp_path):
    config = {"scanner": {"target": "https://example.test", "verified_only": False}}
    reporter = Reporter(config)
    reporter.add_finding(
        Finding(
            plugin="fixture",
            type="Fixture",
            title="Fixture Finding",
            category="test",
            severity="LOW",
            confidence="HIGH",
            surface_id="fixture-1",
            url="https://example.test/",
            evidence={"token": "do-not-leak", "detail": "safe"},
            remediation="none",
            reproduction={"cookie": "session-secret"},
            verification_status="detected",
            scanner_mode="test",
            reproducible=True,
        )
    )
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    reporter.generate_json(str(json_path))
    reporter.generate_html(str(html_path))
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    for secret in ("do-not-leak", "session-secret"):
        assert secret not in json_text
        assert secret not in html_text
    assert "***redacted***" in json_text
    assert "***redacted***" in html_text
