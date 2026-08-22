import json

import yaml

from core.cli import _apply_strategy_override, _report_matches_gate, _strategies_data


def write_report(path, findings):
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")


def test_gate_can_ignore_low_detected_findings(tmp_path):
    report = tmp_path / "scan_report.json"
    write_report(
        report,
        [
            {
                "severity": "LOW",
                "verification_status": "detected",
            }
        ],
    )
    assert not _report_matches_gate(
        report,
        minimum_severity="high",
        minimum_verification="verified",
    )


def test_gate_fails_when_finding_meets_both_thresholds(tmp_path):
    report = tmp_path / "scan_report.json"
    write_report(
        report,
        [
            {"severity": "HIGH", "verification_status": "verified"},
            {"severity": "CRITICAL", "verification_status": "detected"},
        ],
    )
    assert _report_matches_gate(
        report,
        minimum_severity="high",
        minimum_verification="verified",
    )


def test_cli_strategy_override_updates_runtime_config(tmp_path):
    runtime = tmp_path / "runtime.yaml"
    runtime.write_text(
        yaml.safe_dump(
            {
                "scanner": {
                    "strategy": "balanced",
                    "scope": {},
                    "crawler": {},
                    "concurrency": {},
                    "browser": {},
                    "request": {},
                    "active_checks": {},
                    "attack_policy": {},
                    "checkpoint": {},
                    "passive_checks": {},
                    "output": {},
                }
            }
        ),
        encoding="utf-8",
    )

    _apply_strategy_override(runtime, "deep")

    rendered = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    assert rendered["scanner"]["strategy"] == "deep"


def test_strategy_listing_is_user_facing_and_ordered():
    strategies = _strategies_data()
    assert [item["name"] for item in strategies] == [
        "lightweight",
        "balanced",
        "deep",
    ]
    assert all(item["purpose"] for item in strategies)
