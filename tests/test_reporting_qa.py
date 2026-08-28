from __future__ import annotations

import json

from core.models import Finding
from core.reporter import Reporter
from core.sarif import convert_report
from core.utils import redact_text, sanitize_config, setup_logger


def _config(tmp_path):
    return {
        "scanner": {
            "target": "http://127.0.0.1:8080",
            "verified_only": False,
            "scope": {"allowlist": [], "include_domains": ["127.0.0.1:8080"], "exclude_paths": []},
            "auth": {
                "headers": {"Authorization": "Bearer top-secret-token"},
                "cookies": {"session": "super-secret-cookie"},
            },
        },
        "logging": {"file": str(tmp_path / "scanner.log")},
    }


def _finding(url="http://127.0.0.1:8080/sqli?id=1"):
    return Finding(
        plugin="sqli",
        type="SQL Injection",
        title="SQL Injection Signal",
        category="injection",
        severity="HIGH",
        confidence="HIGH",
        surface_id="surface-1",
        url=url,
        evidence={
            "signal": "sql_error_pattern",
            "Authorization": "Bearer finding-secret",
            "nested": {"cookie": "session=finding-cookie"},
        },
        remediation="Use parameterized queries.",
        reproduction={"param": "id", "payload": "'"},
        verification_status="detected",
        scanner_mode="active-web",
    )


def test_json_report_redacts_auth_material(tmp_path):
    reporter = Reporter(_config(tmp_path), scan_meta={"status": "completed", "execution": {}})
    reporter.add_finding(_finding())
    output = tmp_path / "report.json"
    reporter.generate_json(str(output))
    raw = output.read_text(encoding="utf-8")
    data = json.loads(raw)

    assert "top-secret-token" not in raw
    assert "super-secret-cookie" not in raw
    assert "finding-secret" not in raw
    assert "finding-cookie" not in raw
    assert data["findings"][0]["evidence"]["Authorization"] == "***redacted***"
    assert data["findings"][0]["evidence"]["nested"]["cookie"] == "***redacted***"


def test_html_report_escapes_non_http_url_and_redacts_evidence(tmp_path):
    reporter = Reporter(_config(tmp_path), scan_meta={"status": "completed", "execution": {}})
    reporter.add_finding(_finding(url="javascript:alert(1)"))
    output = tmp_path / "report.html"
    reporter.generate_html(str(output))
    raw = output.read_text(encoding="utf-8")

    assert 'href="javascript:' not in raw
    assert "finding-secret" not in raw
    assert "finding-cookie" not in raw
    assert "***redacted***" in raw


def test_sarif_round_trip_from_generated_json(tmp_path):
    reporter = Reporter(_config(tmp_path), scan_meta={"status": "completed", "execution": {}})
    reporter.add_finding(_finding())
    json_output = tmp_path / "report.json"
    sarif_output = tmp_path / "report.sarif"
    reporter.generate_json(str(json_output))
    convert_report(json_output, sarif_output)

    sarif = json.loads(sarif_output.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][0]["ruleId"].startswith("web-vuln-scanner/")


def test_free_form_log_redaction_covers_bearer_jwt_and_assignments():
    raw = (
        "Authorization=secret123 Bearer abc.DEF-ghi_123 "
        "password=hunter2 token=plain eyJabcdefgh.abcdefgh.abcdefgh"
    )
    redacted = redact_text(raw)
    assert "secret123" not in redacted
    assert "hunter2" not in redacted
    assert "token=plain" not in redacted
    assert "***redacted***" in redacted


def test_config_redaction_is_recursive():
    config = {
        "scanner": {
            "auth": {"headers": {"Authorization": "Bearer abc"}},
            "nested": {"api_key": "key-123", "safe": "value"},
        }
    }
    redacted = sanitize_config(config)
    assert redacted["scanner"]["auth"]["headers"]["Authorization"] == "***redacted***"
    assert redacted["scanner"]["nested"]["api_key"] == "***redacted***"
    assert redacted["scanner"]["nested"]["safe"] == "value"


def test_logger_falls_back_to_stream_when_file_handler_cannot_open(monkeypatch):
    def fail_file_handler(*args, **kwargs):
        raise PermissionError("synthetic read-only working directory")

    monkeypatch.setattr("core.utils.logging.FileHandler", fail_file_handler)
    configured = setup_logger(log_file="/synthetic-read-only/scanner.log")
    assert configured.name == "WebVulnScanner"


def test_config_redaction_mixed_case_and_nested():
    """Ensure mixed-case keys and deeply nested dictionaries/lists redact secrets correctly while preserving safe keys."""
    config = {
        "authOrIzAtIoN": "Bearer fake-token-123",
        "cOoKiE": "fake-cookie-456",
        "nested_list": [
            {"aPi_KeY": "fake-api-key-789"},
            {"CsRf": "fake-csrf-token-abc"},
            {"safe_field": "keep-me-intact"},
        ],
        "nested_dict": {
            "level2": {
                "SeCrEt": "fake-secret-xyz",
                "normal_config": "enabled",
                "port": 8080,
            }
        },
        "unrelated": "normal-value",
    }
    redacted = sanitize_config(config)

    # Assert secret/sensitive fields are redacted
    assert redacted["authOrIzAtIoN"] == "***redacted***"
    assert redacted["cOoKiE"] == "***redacted***"
    assert redacted["nested_list"][0]["aPi_KeY"] == "***redacted***"
    assert redacted["nested_list"][1]["CsRf"] == "***redacted***"
    assert redacted["nested_dict"]["level2"]["SeCrEt"] == "***redacted***"

    # Assert safe unrelated fields remain completely unchanged
    assert redacted["nested_list"][2]["safe_field"] == "keep-me-intact"
    assert redacted["nested_dict"]["level2"]["normal_config"] == "enabled"
    assert redacted["nested_dict"]["level2"]["port"] == 8080
    assert redacted["unrelated"] == "normal-value"


def test_free_form_log_redaction_various_formats():
    """Ensure free-form log strings containing bearer tokens, JWTs, and secret assignments are redacted properly."""
    # Bearer tokens in logs (various formats/cases)
    bearer_log = "DEBUG - Authorization header contains: Bearer abc_123-xyz.tuv~+"
    redacted_bearer = redact_text(bearer_log)
    assert "abc_123-xyz" not in redacted_bearer
    assert "Bearer ***redacted***" in redacted_bearer

    # JWT tokens in logs (various formats)
    jwt_log = "ERROR - Found token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    redacted_jwt = redact_text(jwt_log)
    assert "eyJhbGciOi" not in redacted_jwt
    assert "***redacted-jwt***" in redacted_jwt

    # Mixed-case assignments with spaces, colons, equals, etc.
    assignments_log = "Passwd:  my-fake-password, Api_Key=my-fake-api-key, csrF=my-fake-csrf"
    redacted_assignments = redact_text(assignments_log)
    assert "my-fake-password" not in redacted_assignments
    assert "my-fake-api-key" not in redacted_assignments
    assert "my-fake-csrf" not in redacted_assignments
    assert "Passwd:  ***redacted***" in redacted_assignments
    assert "Api_Key=***redacted***" in redacted_assignments
    assert "csrF=***redacted***" in redacted_assignments

    # Unrelated log info remains unchanged
    safe_log = "INFO - Task 543 completed successfully at host 192.168.1.1 on port 443"
    assert redact_text(safe_log) == safe_log
