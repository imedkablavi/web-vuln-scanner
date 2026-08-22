import json
import os

import pytest

from core.models import AttackSurface, Finding
from core.scan_checkpoint import (
    ScanCheckpoint,
    testcase_fingerprint as checkpoint_testcase_fingerprint,
)
from core.scanner import ScannerEngine
from plugins.base import BasePlugin, TestCase, VerificationResult


class Response:
    status_code = 200
    text = "ok"
    headers = {}


class Requester:
    def __init__(self):
        self.baselines = 0
        self.active = 0

    def send_surface(self, surface, param=None, payload=None):
        if param is None:
            self.baselines += 1
        else:
            self.active += 1
        return Response()


class FixturePlugin(BasePlugin):
    name = "fixture"

    def __init__(self, requester, config, *, fail_param=""):
        super().__init__(requester, config)
        self.fail_param = fail_param

    def applicable(self, surface):
        return True

    def generate_tests(self, surface, context):
        return [
            TestCase(
                plugin=self.name,
                surface_id=surface.id,
                param="first",
                kind="query",
                payload="probe-one",
            ),
            TestCase(
                plugin=self.name,
                surface_id=surface.id,
                param="second",
                kind="query",
                payload="probe-two",
            ),
        ]

    def verify(self, testcase, baseline, response, context):
        if testcase.param == self.fail_param:
            raise RuntimeError("fixture interrupted")
        return VerificationResult(
            True,
            "HIGH",
            {"param": testcase.param, "password": "response-secret"},
            {"param": testcase.param, "payload": testcase.payload},
            severity="MEDIUM",
            verification_status="detected",
        )

    def build_finding(self, testcase, vres, surface):
        return Finding(
            plugin=self.name,
            type=f"fixture-{testcase.param}",
            title=f"Fixture {testcase.param}",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="fixture",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active",
            reproducible=True,
        )


def scanner_config(path, *, resume=False, keep_completed=False):
    return {
        "scanner": {
            "target": "https://example.test/",
            "profile": "safe-active",
            "concurrency": {
                "threads": 1,
                "per_host_concurrency": 1,
                "timeout": 1,
                "global_timeout_seconds": 5,
            },
            "plugins": {},
            "attack_policy": {},
            "max_findings_per_plugin": 10,
            "checkpoint": {
                "enabled": True,
                "path": str(path),
                "resume": resume,
                "flush_every": 1,
                "keep_completed": keep_completed,
            },
        }
    }


def sample_finding():
    return Finding(
        plugin="fixture",
        type="fixture-first",
        title="Fixture first",
        severity="MEDIUM",
        confidence="HIGH",
        surface_id="surface",
        url="https://example.test/item?access_token=url-secret",
        evidence={"password": "evidence-secret", "detail": "safe"},
        remediation="fixture",
        reproduction={"param": "first", "payload": "probe-one"},
        verification_status="detected",
        scanner_mode="active",
        reproducible=True,
    )


def test_checkpoint_round_trip_is_secret_minimized_and_restrictive(tmp_path):
    path = tmp_path / "resume.json"
    config = scanner_config(path)["scanner"]
    checkpoint = ScanCheckpoint.from_scanner_config(config)
    assert checkpoint is not None

    surface = AttackSurface(
        url="https://example.test/item?first=1",
        method="GET",
        params={"first": "1"},
        source="fixture",
    )
    testcase = TestCase(
        plugin="fixture",
        surface_id=surface.id,
        param="first",
        kind="query",
        payload="probe-one",
    )
    key = checkpoint_testcase_fingerprint("fixture", surface, testcase)
    checkpoint.record_completed(key, sample_finding())
    checkpoint.finalize(completed=False)

    rendered = path.read_text(encoding="utf-8")
    assert "evidence-secret" not in rendered
    assert "url-secret" not in rendered
    assert "***redacted***" in rendered
    assert "probe-one" in rendered  # reproduction is non-secret assessment evidence
    if os.name != "nt":
        assert (path.stat().st_mode & 0o777) == 0o600

    resume_config = scanner_config(path, resume=True)["scanner"]
    resumed = ScanCheckpoint.from_scanner_config(resume_config)
    assert resumed is not None
    assert resumed.is_completed(key) is True
    restored = resumed.restored_findings()
    assert len(restored) == 1
    assert restored[0].fingerprint == sample_finding().fingerprint
    assert restored[0].evidence["password"] == "***redacted***"


def test_checkpoint_rejects_target_or_config_mismatch(tmp_path):
    path = tmp_path / "resume.json"
    config = scanner_config(path)["scanner"]
    checkpoint = ScanCheckpoint.from_scanner_config(config)
    checkpoint.finalize(completed=False)

    different_target = scanner_config(path, resume=True)["scanner"]
    different_target["target"] = "https://other.test/"
    with pytest.raises(ValueError, match="target does not match"):
        ScanCheckpoint.from_scanner_config(different_target)

    different_plugins = scanner_config(path, resume=True)["scanner"]
    different_plugins["plugins"] = {"sqli": {"enabled": True}}
    with pytest.raises(ValueError, match="configuration does not match"):
        ScanCheckpoint.from_scanner_config(different_plugins)


def test_completed_checkpoint_is_not_treated_as_a_stale_resume(tmp_path):
    path = tmp_path / "resume.json"
    config = scanner_config(path, keep_completed=True)["scanner"]
    checkpoint = ScanCheckpoint.from_scanner_config(config)
    checkpoint.finalize(completed=True)
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "completed"

    resume_config = scanner_config(path, resume=True, keep_completed=True)["scanner"]
    with pytest.raises(ValueError, match="not resumable"):
        ScanCheckpoint.from_scanner_config(resume_config)


def test_scanner_resume_skips_completed_testcase_and_restores_finding(tmp_path):
    path = tmp_path / "resume.json"
    surface = AttackSurface(
        url="https://example.test/item",
        method="GET",
        params={"first": "1", "second": "2"},
        source="fixture",
    )

    first_requester = Requester()
    first_engine = ScannerEngine(first_requester, scanner_config(path))
    first_engine.plugins = [
        FixturePlugin(first_requester, {}, fail_param="second")
    ]
    first_findings = first_engine.scan([surface])
    assert [item.type for item in first_findings] == ["fixture-first"]
    assert first_requester.active == 2
    assert path.exists()
    assert first_engine.last_run_stats["checkpoint"]["status"] == "partial"

    second_requester = Requester()
    second_engine = ScannerEngine(
        second_requester,
        scanner_config(path, resume=True),
    )
    second_engine.plugins = [FixturePlugin(second_requester, {})]
    resumed_findings = second_engine.scan([surface])

    assert {item.type for item in resumed_findings} == {
        "fixture-first",
        "fixture-second",
    }
    assert second_requester.active == 1
    assert second_engine.last_run_stats["resumed_testcases"] == 1
    assert second_engine.last_run_stats["restored_findings"] == 1
    assert second_engine.last_run_stats["checkpoint"]["status"] == "completed"
    assert not path.exists()