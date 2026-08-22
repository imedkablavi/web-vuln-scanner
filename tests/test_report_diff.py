from core.report_diff import (
    compare_report_data,
    finding_fingerprint,
    new_findings_at_or_above,
    regressions,
)


def finding(
    *,
    plugin="web_posture",
    type_="Missing Security Headers",
    title="Headers incomplete",
    severity="LOW",
    verification="detected",
    url="https://example.test/app?b=2&a=1",
    param="",
):
    return {
        "plugin": plugin,
        "type": type_,
        "title": title,
        "severity": severity,
        "verification_status": verification,
        "url": url,
        "category": "misconfiguration",
        "reproduction": {"param": param} if param else {},
        "evidence": {"volatile": "ignored"},
    }


def test_fingerprint_is_stable_across_evidence_query_order_and_title_wording():
    first = finding(
        url="https://example.test/app?b=2&a=1",
        title="Browser security headers are incomplete",
    )
    second = finding(
        url="https://EXAMPLE.test/app?a=1&b=2",
        title="Missing recommended browser headers",
    )
    second["evidence"] = {"different": "value"}
    assert finding_fingerprint(first) == finding_fingerprint(second)


def test_diff_reports_new_fixed_changed_and_unchanged():
    unchanged = finding()
    changed_before = finding(type_="SQL Injection", title="SQLi", severity="MEDIUM")
    changed_after = finding(
        type_="SQL Injection",
        title="SQL injection confirmed",
        severity="HIGH",
        verification="verified",
    )
    fixed = finding(type_="Verbose Error", title="Verbose error", url="https://example.test/old")
    new = finding(type_="Weak CSP", title="Weak CSP", severity="MEDIUM", url="https://example.test/new")

    diff = compare_report_data(
        {"findings": [unchanged, changed_before, fixed]},
        {"findings": [unchanged, changed_after, new]},
    )
    assert diff["summary"] == {
        "baseline_findings": 3,
        "current_findings": 3,
        "new": 1,
        "fixed": 1,
        "changed": 1,
        "unchanged": 1,
    }
    assert diff["new"][0]["type"] == "Weak CSP"
    assert diff["fixed"][0]["type"] == "Verbose Error"
    assert diff["changed"][0]["before"]["severity"] == "MEDIUM"
    assert diff["changed"][0]["after"]["severity"] == "HIGH"


def test_title_only_change_remains_unchanged_issue():
    before = finding(title="Old wording")
    after = finding(title="Improved wording")
    diff = compare_report_data({"findings": [before]}, {"findings": [after]})
    assert diff["summary"]["new"] == 0
    assert diff["summary"]["fixed"] == 0
    assert diff["summary"]["changed"] == 0
    assert diff["summary"]["unchanged"] == 1


def test_new_finding_gate_respects_minimum_severity():
    diff = compare_report_data(
        {"findings": []},
        {
            "findings": [
                finding(type_="Low", title="Low", severity="LOW", url="https://example.test/low"),
                finding(type_="High", title="High", severity="HIGH", url="https://example.test/high"),
            ]
        },
    )
    gated = new_findings_at_or_above(diff, "high")
    assert [item["severity"] for item in gated] == ["HIGH"]


def test_regressions_include_existing_findings_that_get_stronger():
    before = finding(severity="LOW", verification="suspected")
    after = finding(severity="MEDIUM", verification="verified")
    diff = compare_report_data({"findings": [before]}, {"findings": [after]})
    assert len(regressions(diff)) == 1
