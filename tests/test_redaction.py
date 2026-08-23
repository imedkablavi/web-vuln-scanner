import json

from core.models import Finding
from core.redaction import REDACTED, redact_structure, redact_text
from core.reporter import Reporter


def _finding(secret: str) -> Finding:
    return Finding(
        plugin="data_exposure",
        type="Sensitive Data Indicator",
        title="Sensitive data",
        category="data-exposure",
        severity="HIGH",
        confidence="HIGH",
        surface_id="test:redaction",
        url="https://example.test/debug",
        evidence={
            "response_excerpt": f"DB_PASSWORD={secret}",
            "nested": {"Authorization": f"Bearer {secret}"},
        },
        remediation="Remove secrets",
        reproduction={"method": "GET", "url": "https://example.test/debug"},
        verification_status="detected",
        scanner_mode="data-exposure",
        reproducible=True,
    )


def test_redact_text_removes_secret_assignments_and_auth_headers():
    secret = "SUPERSECRET-7f918-test-value"
    raw = (
        f"password={secret} Authorization: Bearer {secret} "
        f"https://u:{secret}@example.test/"
    )
    redacted = redact_text(raw)
    assert secret not in redacted
    assert REDACTED in redacted


def test_redact_text_removes_serialized_json_secrets():
    password = "demo-pass-json-sentinel"
    api_key = "mock-debug-key-json-sentinel"
    raw = json.dumps(
        {"debug": True, "password": password, "api_key": api_key}
    )
    redacted = redact_text(raw)
    assert password not in redacted
    assert api_key not in redacted
    parsed = json.loads(redacted)
    assert parsed["password"] == REDACTED
    assert parsed["api_key"] == REDACTED


def test_redact_text_covers_json_fragment_when_full_parse_is_impossible():
    secret = "fragment-secret-sentinel"
    raw = f'prefix {{"password": "{secret}"}} suffix'
    redacted = redact_text(raw)
    assert secret not in redacted
    assert REDACTED in redacted


def test_redact_structure_preserves_metadata_but_removes_values():
    secret = "TOKEN-should-never-persist"
    value = {
        "cookie_names": ["session"],
        "access_token": secret,
        "excerpt": f"api_key={secret}",
    }
    redacted = redact_structure(value)
    assert redacted["cookie_names"] == ["session"]
    assert redacted["access_token"] == REDACTED
    assert secret not in json.dumps(redacted)


def test_reporter_never_persists_detected_secret(tmp_path):
    secret = "SUPERSECRET-7f918-report-sentinel"
    reporter = Reporter(
        {
            "scanner": {
                "target": "https://example.test",
                "scope": {},
                "verified_only": False,
            }
        },
        scan_meta={
            "status": "completed",
            "execution": {
                "layers": {"debug": {"excerpt": f"token={secret}"}}
            },
        },
    )
    reporter.add_finding(_finding(secret))

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    reporter.generate_json(str(json_path))
    reporter.generate_html(str(html_path))

    assert secret not in json_path.read_text(encoding="utf-8")
    assert secret not in html_path.read_text(encoding="utf-8")
