from __future__ import annotations

from core.models import AttackSurface
from core.request_manager import RequestManager
from core.scanner import PluginRegistry, ScannerEngine
from tests.local_corpus import run_regression_corpus


EXPERIMENTAL = ("xss_reflected", "lfi", "cmd_injection", "open_redirect")


def _config(base_url: str, plugin: str | None = None, *, allow_experimental: bool = True):
    hostport = base_url.split("//", 1)[1]
    plugins = {
        "sqli": {"enabled": plugin == "sqli", "max_tests_per_surface": 5, "request_budget": 5, "timeout_seconds": 2, "min_length_delta_ratio": 0.05},
        "business_logic": {"enabled": False},
        "xss_reflected": {"enabled": plugin == "xss_reflected", "max_tests_per_surface": 3, "request_budget": 3, "timeout_seconds": 2, "max_params": 2},
        "lfi": {"enabled": plugin == "lfi", "max_tests_per_surface": 4, "request_budget": 4, "timeout_seconds": 2, "max_params": 1},
        "cmd_injection": {
            "enabled": plugin == "cmd_injection",
            "allow_command_probe": plugin == "cmd_injection",
            "max_tests_per_surface": 2,
            "request_budget": 2,
            "timeout_seconds": 2,
            "max_params": 1,
        },
        "open_redirect": {"enabled": plugin == "open_redirect", "max_tests_per_surface": 2, "request_budget": 2, "timeout_seconds": 2, "max_params": 2},
    }
    return {
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
        "scope": {"include_domains": [hostport], "allow_private": True},
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
        "plugin_contract": "v2",
        "verified_only": False,
        "max_findings_per_plugin": 10,
        "allow_experimental_plugins": allow_experimental,
        "plugins": plugins,
    }


def _scan(base_url: str, plugin: str, path: str, params: dict[str, str]):
    config = _config(base_url, plugin)
    manager = RequestManager(config)
    engine = ScannerEngine(manager, config)
    surface = AttackSurface(
        url=f"{base_url}{path}",
        method="GET",
        params=params,
        source="local-regression-corpus",
    )
    findings = engine.scan([surface])
    return engine, [finding for finding in findings if finding.plugin == plugin]


def test_experimental_plugins_require_global_opt_in():
    with run_regression_corpus() as (_, base_url):
        config = _config(base_url, "xss_reflected", allow_experimental=False)
        manager = RequestManager(config)
        loaded = {plugin.name for plugin in PluginRegistry.load_plugins(config, manager)}
    assert "xss_reflected" not in loaded


def test_experimental_plugins_require_request_manager_host_scope():
    with run_regression_corpus() as (_, base_url):
        hostport = base_url.split("//", 1)[1]
        config = _config(base_url, "xss_reflected")
        config["scope"]["include_domains"] = []
        config["scope"]["allowlist"] = [hostport]
        manager = RequestManager(config)
        loaded = {plugin.name for plugin in PluginRegistry.load_plugins(config, manager)}
    assert "xss_reflected" not in loaded


def test_command_injection_requires_secondary_opt_in():
    with run_regression_corpus() as (_, base_url):
        config = _config(base_url, "cmd_injection")
        config["plugins"]["cmd_injection"]["allow_command_probe"] = False
        manager = RequestManager(config)
        loaded = {plugin.name for plugin in PluginRegistry.load_plugins(config, manager)}
    assert "cmd_injection" not in loaded


def test_xss_structural_positive_and_escaped_negative():
    with run_regression_corpus() as (_, base_url):
        positive_engine, positive = _scan(base_url, "xss_reflected", "/experimental/xss", {"q": "hello"})
        _, negative = _scan(base_url, "xss_reflected", "/experimental/xss-safe", {"q": "hello"})

    assert any(f.verification_status == "detected" and f.confidence == "HIGH" for f in positive)
    assert negative == []
    assert positive_engine.last_run_stats["plugin_details"]["xss_reflected"]["executed_requests"] <= 3


def test_lfi_signature_positive_and_constant_negative():
    with run_regression_corpus() as (_, base_url):
        positive_engine, positive = _scan(base_url, "lfi", "/experimental/lfi", {"file": "help.txt"})
        _, negative = _scan(base_url, "lfi", "/experimental/lfi-safe", {"file": "help.txt"})

    assert any(f.verification_status == "detected" and f.evidence.get("signature") in {"unix_passwd", "windows_win_ini"} for f in positive)
    assert negative == []
    assert positive_engine.last_run_stats["plugin_details"]["lfi"]["executed_requests"] <= 4


def test_command_marker_positive_and_safe_negative():
    with run_regression_corpus() as (_, base_url):
        positive_engine, positive = _scan(base_url, "cmd_injection", "/experimental/cmd", {"cmd": "status"})
        _, negative = _scan(base_url, "cmd_injection", "/experimental/cmd-safe", {"cmd": "status"})

    assert any(f.verification_status == "detected" and f.evidence.get("signal") == "command_output_marker" for f in positive)
    assert negative == []
    assert positive_engine.last_run_stats["plugin_details"]["cmd_injection"]["executed_requests"] <= 2


def test_open_redirect_exact_external_location_positive_and_local_negative():
    with run_regression_corpus() as (_, base_url):
        positive_engine, positive = _scan(base_url, "open_redirect", "/experimental/redirect", {"next": "/safe"})
        _, negative = _scan(base_url, "open_redirect", "/experimental/redirect-safe", {"next": "/safe"})

    assert any(f.verification_status == "verified" and f.evidence.get("location_host") == "redirect.invalid" for f in positive)
    assert negative == []
    assert positive_engine.last_run_stats["plugin_details"]["open_redirect"]["executed_requests"] <= 2


def test_sqli_positive_safe_negative_and_static_error_negative():
    with run_regression_corpus() as (_, base_url):
        _, positive = _scan(base_url, "sqli", "/sqli", {"id": "1"})
        _, safe_negative = _scan(base_url, "sqli", "/safe", {"id": "1"})
        _, baseline_error_negative = _scan(base_url, "sqli", "/sqli-baseline-error", {"id": "1"})

    assert any(f.verification_status in {"detected", "verified"} for f in positive)
    assert safe_negative == []
    assert baseline_error_negative == []
