from __future__ import annotations

from core.models import AttackSurface, InputField
from core.scanner import ScannerEngine


class Response:
    status_code = 200
    text = "ok"
    headers = {}

    def __bool__(self):
        return True


class Requester:
    def __init__(self):
        self.calls = []

    def send_surface(self, surface, *args, **kwargs):
        self.calls.append((surface.method, surface.url))
        return Response()


def config():
    return {
        "scanner": {
            "plugins": {},
            "concurrency": {
                "threads": 1,
                "per_host_concurrency": 1,
                "timeout": 1,
                "global_timeout_seconds": 5,
            },
            "plugin_contract": "v2",
            "verified_only": False,
            "max_findings_per_plugin": 10,
            "attack_policy": {
                "skip_parameters": [],
                "skip_parameter_patterns": [],
            },
            "checkpoint": {"enabled": False},
        }
    }


def test_inventory_only_post_surface_sends_no_baseline_or_plugin_request():
    requester = Requester()
    engine = ScannerEngine(requester, config())
    surface = AttackSurface(
        url="https://example.test/account",
        method="PATCH",
        inputs=[InputField(name="email", kind="body", path="/profile/email")],
        source="postman",
        meta={"active_eligible": False, "content_type": "application/json"},
    )

    findings = engine.scan([surface])

    assert findings == []
    assert requester.calls == []
    assert engine.last_run_stats["inventory_only_surfaces"] == 1
    assert engine.last_run_stats["errors"] == []


def test_legacy_surface_without_flag_keeps_previous_baseline_behavior():
    requester = Requester()
    engine = ScannerEngine(requester, config())
    surface = AttackSurface(
        url="https://example.test/search",
        method="GET",
        params={"q": ""},
        source="crawler",
    )

    engine.scan([surface])

    assert requester.calls == [("GET", "https://example.test/search")]
    assert engine.last_run_stats["inventory_only_surfaces"] == 0
