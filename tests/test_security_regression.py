from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.models import AttackSurface, AuthActor
from core.request_manager import RequestManager
from core.scanner import PluginRegistry, ScannerEngine
from plugins.base import BasePlugin, TestCase, VerificationResult
from tests.local_corpus import run_regression_corpus


def _request_config(base_url: str, *, max_retries: int = 0):
    hostport = base_url.split("//", 1)[1]
    return {
        "concurrency": {
            "delay": 0,
            "max_retries": max_retries,
            "timeout": 1,
            "threads": 1,
            "per_host_concurrency": 1,
            "global_timeout_seconds": 5,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": max_retries,
            "follow_redirects": False,
        },
        "scope": {"include_domains": [hostport], "allow_private": True},
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def _scanner_config(base_url: str):
    cfg = _request_config(base_url)
    cfg.update(
        {
            "plugin_contract": "v2",
            "verified_only": False,
            "max_findings_per_plugin": 10,
            "plugins": {
                "sqli": {
                    "enabled": True,
                    "max_tests_per_surface": 3,
                    "request_budget": 3,
                    "timeout_seconds": 2,
                    "time_based": False,
                    "min_length_delta_ratio": 0.05,
                },
                "business_logic": {"enabled": False},
                "xss_reflected": {"enabled": False},
                "lfi": {"enabled": False},
                "cmd_injection": {"enabled": False},
                "open_redirect": {"enabled": False},
            },
        }
    )
    return cfg


def test_local_corpus_detects_known_sqli_signal_without_external_network():
    with run_regression_corpus() as (_, base_url):
        config = _scanner_config(base_url)
        manager = RequestManager(config)
        engine = ScannerEngine(manager, config)
        surface = AttackSurface(url=f"{base_url}/sqli", method="GET", params={"id": "1"}, source="regression-corpus")
        findings = engine.scan([surface])

    assert any(f.plugin == "sqli" and f.verification_status in {"detected", "verified"} for f in findings)
    assert engine.last_run_stats["plugin_details"]["sqli"]["executed_requests"] <= 3


def test_local_corpus_safe_endpoint_does_not_create_sqli_false_positive():
    with run_regression_corpus() as (_, base_url):
        config = _scanner_config(base_url)
        manager = RequestManager(config)
        engine = ScannerEngine(manager, config)
        surface = AttackSurface(url=f"{base_url}/safe", method="GET", params={"id": "1"}, source="regression-corpus")
        findings = engine.scan([surface])

    assert [f for f in findings if f.plugin == "sqli"] == []


def test_authenticated_actor_cookie_is_used_only_for_that_actor():
    with run_regression_corpus() as (_, base_url):
        manager = RequestManager(_request_config(base_url))
        anonymous = manager.send("GET", f"{base_url}/auth/profile")
        actor = AuthActor(actor_id="low", display_name="Low User", auth_type="cookie", cookies={"session": "user-token"})
        authenticated = manager.send_as_actor("GET", f"{base_url}/auth/profile", actor=actor)
        after = manager.send("GET", f"{base_url}/auth/profile")

    assert anonymous.status_code == 401
    assert authenticated.status_code == 200
    assert after.status_code == 401


def test_scope_enforcement_blocks_out_of_scope_actor_request_before_network(monkeypatch):
    config = _request_config("http://127.0.0.1:65530")
    manager = RequestManager(config)
    called = False

    def fake_request(**kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    actor = AuthActor(actor_id="low", display_name="Low User", auth_type="cookie", cookies={"session": "user-token"})
    with pytest.raises(RuntimeError, match="not allowed by scope"):
        manager.send_as_actor("GET", "https://outside.example/profile", actor=actor)
    assert called is False


def test_rate_limit_retry_is_bounded_and_honors_retry_after():
    with run_regression_corpus() as (server, base_url):
        manager = RequestManager(_request_config(base_url, max_retries=2))
        response = manager.send("GET", f"{base_url}/rate-limit")

    assert response.status_code == 200
    assert server.rate_limit_hits == 3


def test_experimental_plugins_remain_unloadable_even_if_config_requests_them():
    with run_regression_corpus() as (_, base_url):
        config = _scanner_config(base_url)
        for name in ("xss_reflected", "lfi", "cmd_injection", "open_redirect"):
            config["plugins"][name]["enabled"] = True
        manager = RequestManager(config)
        loaded = {plugin.name for plugin in PluginRegistry.load_plugins(config, manager)}

    assert loaded == {"sqli"}


class _ContractPlugin(BasePlugin):
    name = "contract-test"
    supported_input_kinds = ["query"]

    def applicable(self, surface):
        return True

    def generate_tests(self, surface, context):
        return [
            TestCase(plugin=self.name, surface_id=surface.id, param="q", kind="query", payload=str(index))
            for index in range(3)
        ]

    def verify(self, testcase, baseline, response, context):
        return VerificationResult(False, "LOW", {"reason": "synthetic"}, {}, verification_status="not_reproducible")

    def build_finding(self, testcase, vres, surface):  # pragma: no cover - result is non-reportable
        raise AssertionError("not expected")


class _FakeRequester:
    def __init__(self):
        self.calls = 0

    def send_surface(self, surface, param_to_inject=None, payload=None, actor=None, replay_of=""):
        self.calls += 1
        return SimpleNamespace(status_code=200, headers={}, text="constant", url=surface.url)


def test_plugin_request_budget_is_enforced(monkeypatch):
    requester = _FakeRequester()
    plugin = _ContractPlugin(requester, {"enabled": True, "max_tests_per_surface": 3, "request_budget": 1, "timeout_seconds": 2})
    monkeypatch.setattr(PluginRegistry, "load_plugins", classmethod(lambda cls, config, request_manager: [plugin]))
    config = {
        "concurrency": {"threads": 1, "per_host_concurrency": 1, "timeout": 1, "global_timeout_seconds": 5},
        "plugins": {},
        "plugin_contract": "v2",
        "verified_only": False,
        "max_findings_per_plugin": 5,
    }
    engine = ScannerEngine(requester, config)
    surface = AttackSurface(url="http://local.invalid/safe", method="GET", params={"q": "x"})
    engine.scan([surface])

    stats = engine.last_run_stats["plugin_details"]["contract-test"]
    # One baseline plus one plugin request.
    assert requester.calls == 2
    assert stats["executed_requests"] == 1
    assert stats["contract_violations"] == 1


def test_plugin_contract_rejects_reportable_result_without_evidence():
    plugin = _ContractPlugin(_FakeRequester(), {"enabled": True})
    with pytest.raises(ValueError, match="require evidence"):
        plugin.validate_verification_result(
            VerificationResult(True, "HIGH", {}, {"payload": "x"}, verification_status="verified")
        )
