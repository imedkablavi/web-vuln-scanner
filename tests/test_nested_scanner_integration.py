from __future__ import annotations

from core.models import AttackSurface, InputField
from core.request_manager import RequestManager
from core.scanner import ScannerEngine


class _Response:
    status_code = 200
    text = "stable response"
    headers = {"Content-Type": "text/plain"}


class _CaptureManager:
    send_surface = RequestManager.send_surface

    def __init__(self):
        self.config = {"auth": {"headers": {}}}
        self.cookies = {}
        self.timeout = 2
        self.calls = []

    def send_as_actor(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return _Response()


def _config():
    return {
        "scanner": {
            "concurrency": {
                "threads": 1,
                "per_host_concurrency": 1,
                "timeout": 2,
                "global_timeout_seconds": 30,
            },
            "plugins": {
                "sqli": {
                    "enabled": True,
                    "max_tests_per_surface": 20,
                    "min_length_delta_ratio": 0.05,
                }
            },
            "attack_policy": {"skip_parameters": [], "skip_parameter_patterns": []},
            "plugin_contract": "v2",
            "verified_only": False,
            "max_findings_per_plugin": 10,
            "checkpoint": {"enabled": False},
            "debug": False,
        }
    }


def _surface():
    return AttackSurface(
        url="https://example.com/api/review",
        method="POST",
        params={"mode": "edit"},
        inputs=[
            InputField(name="mode", value="edit", kind="query", path="mode"),
            InputField(name="id", value=7, kind="body", path="/owner/id", data_type="integer"),
            InputField(name="id", value=11, kind="body", path="/reviewer/id", data_type="integer"),
            InputField(name="enabled", value=False, kind="body", path="/settings/enabled", data_type="boolean"),
        ],
        source="openapi",
        meta={
            "content_type": "application/json",
            "body_format": "json",
            "active_eligible": True,
        },
    )


def test_scanner_nested_json_baseline_and_candidates_share_transport_shape():
    manager = _CaptureManager()
    scanner = ScannerEngine(manager, _config())

    findings = scanner.scan([_surface()])

    assert findings == []
    assert len(manager.calls) >= 3

    baseline = manager.calls[0]
    assert baseline[0] == "POST"
    assert baseline[2]["params"] == {"mode": "edit"}
    assert baseline[2]["json"] == {
        "owner": {"id": 7},
        "reviewer": {"id": 11},
        "settings": {"enabled": False},
    }

    candidate_jsons = [call[2]["json"] for call in manager.calls[1:]]
    owner_candidates = [
        body
        for body in candidate_jsons
        if body["owner"]["id"] != 7 and body["reviewer"]["id"] == 11
    ]
    reviewer_candidates = [
        body
        for body in candidate_jsons
        if body["owner"]["id"] == 7 and body["reviewer"]["id"] != 11
    ]
    assert owner_candidates
    assert reviewer_candidates
    assert all(body["settings"]["enabled"] is False for body in owner_candidates)
    assert all(body["settings"]["enabled"] is False for body in reviewer_candidates)
    assert all(call[2]["params"] == {"mode": "edit"} for call in manager.calls)
