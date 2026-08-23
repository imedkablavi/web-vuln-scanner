import time
from types import SimpleNamespace

from core.models import AttackSurface, Finding
from core.scanner import PluginRegistry, ScannerEngine
from plugins.base import BasePlugin, TestCase, VerificationResult


class FakeRequester:
    def send_surface(self, surface, param_to_inject=None, payload=None):
        return SimpleNamespace(status_code=200, text="ok", headers={})


class AlwaysFindingPlugin(BasePlugin):
    name = "always"

    def applicable(self, surface):
        return True

    def generate_tests(self, surface, context):
        return [
            TestCase(
                plugin=self.name,
                surface_id=surface.id,
                param="id",
                kind="query",
                payload="1",
            )
        ]

    def verify(self, testcase, baseline, response, context):
        return VerificationResult(
            is_verified=True,
            confidence="HIGH",
            evidence={"signal": "fixture"},
            reproduction={"param": testcase.param},
            verification_status="verified",
        )

    def build_finding(self, testcase, vres, surface):
        return Finding(
            plugin=self.name,
            type="Fixture Finding",
            severity="MEDIUM",
            confidence="HIGH",
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="fixture",
            reproduction=vres.reproduction,
            verification_status="verified",
            reproducible=True,
        )


class SlowPlugin(AlwaysFindingPlugin):
    name = "slow"

    def generate_tests(self, surface, context):
        time.sleep(0.04)
        return super().generate_tests(surface, context)


def make_config(*, cap=2, timeout=5):
    return {
        "scanner": {
            "concurrency": {
                "threads": 1,
                "per_host_concurrency": 1,
                "timeout": 1,
                "global_timeout_seconds": timeout,
            },
            "plugins": {},
            "plugin_contract": "v2",
            "verified_only": False,
            "max_findings_per_plugin": cap,
            "debug": False,
        }
    }


def surfaces(count=5):
    return [
        AttackSurface(
            url=f"https://example.com/item/{index}",
            method="GET",
            params={"id": str(index)},
        )
        for index in range(count)
    ]


def test_experimental_plugin_is_blocked_by_release_maturity_policy():
    config = make_config()
    config["scanner"]["plugins"] = {
        "cmd_injection": {"enabled": True},
        "sqli": {"enabled": False},
    }
    loaded = PluginRegistry.load_plugins(config["scanner"], FakeRequester())
    assert all(plugin.name != "cmd_injection" for plugin in loaded)


def test_max_findings_per_plugin_is_global_across_surfaces(monkeypatch):
    plugin = AlwaysFindingPlugin(FakeRequester(), {"enabled": True})
    monkeypatch.setattr(
        PluginRegistry,
        "load_plugins",
        classmethod(lambda cls, config, requester: [plugin]),
    )
    engine = ScannerEngine(FakeRequester(), make_config(cap=2, timeout=5))
    findings = engine.scan(surfaces(6))

    assert len(findings) == 2
    assert engine.last_run_stats["findings_per_plugin"]["always"] == 2


def test_global_active_scan_timeout_is_reported(monkeypatch):
    plugin = SlowPlugin(FakeRequester(), {"enabled": True})
    monkeypatch.setattr(
        PluginRegistry,
        "load_plugins",
        classmethod(lambda cls, config, requester: [plugin]),
    )
    engine = ScannerEngine(FakeRequester(), make_config(cap=10, timeout=0.02))
    engine.scan(surfaces(3))

    assert engine.last_run_stats["timed_out"] is True
    assert any(
        "global timeout" in message.lower()
        for message in engine.last_run_stats["errors"]
    )
