import json

from core.cli import _report_matches_gate


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
