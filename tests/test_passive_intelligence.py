from layers.csp_checks import check_csp_policy
from layers.stacktrace_checks import detect_stack_trace
from layers.technology_fingerprint import fingerprint_snapshot


def snapshot(**overrides):
    data = {
        "url": "https://example.test/app",
        "status": 200,
        "headers": {"content-type": "text/html"},
        "text": "<html><body>ok</body></html>",
        "content_type": "text/html",
        "set_cookies": [],
        "host": "example.test",
        "path": "/app",
    }
    data.update(overrides)
    return data


def test_fingerprint_combines_header_cookie_and_html_signals_without_cookie_values():
    items = fingerprint_snapshot(
        snapshot(
            headers={
                "content-type": "text/html",
                "server": "nginx/1.27.1",
                "x-powered-by": "PHP/8.4.2",
            },
            set_cookies=["PHPSESSID=super-secret-value; Secure; HttpOnly"],
            text='<meta name="generator" content="WordPress 6.8"><script src="/wp-content/a.js"></script>',
        )
    )
    by_name = {item["name"]: item for item in items}
    assert by_name["Nginx"]["version"] == "1.27.1"
    assert by_name["PHP"]["confidence"] == "HIGH"
    assert by_name["WordPress"]["confidence"] == "HIGH"
    assert "super-secret-value" not in repr(items)


def test_fingerprint_avoids_generic_html_false_positive():
    assert fingerprint_snapshot(snapshot(text="<div id='app'>hello</div>")) == []


def test_csp_reports_risky_script_sources_and_missing_form_action():
    findings = check_csp_policy(
        snapshot(
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' *",
            },
            text="<html><form action='/pay'></form></html>",
        )
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Weak Content Security Policy"
    assert finding.severity == "MEDIUM"
    assert "script-src allows 'unsafe-inline'" in finding.evidence["issues"]
    assert any("form-action" in item for item in finding.evidence["issues"])


def test_csp_report_only_is_distinguished_from_missing_policy():
    findings = check_csp_policy(
        snapshot(
            headers={
                "content-type": "text/html",
                "content-security-policy-report-only": "default-src 'self'",
            }
        )
    )
    assert [finding.type for finding in findings] == [
        "CSP Report-Only Without Enforcement"
    ]


def test_strong_csp_has_no_posture_finding():
    findings = check_csp_policy(
        snapshot(
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; form-action 'self'; frame-ancestors 'none'",
            },
            text="<form></form>",
        )
    )
    assert findings == []


def test_python_stack_trace_is_detected_without_copying_response_text():
    body = (
        "Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 41, in handler\n'
        "ValueError: internal-token-should-not-be-copied"
    )
    findings = detect_stack_trace(snapshot(status=500, text=body))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Stack Trace Disclosure"
    assert finding.evidence["detected_runtimes"][0]["engine"] == "Python"
    assert "internal-token-should-not-be-copied" not in repr(finding.evidence)


def test_ordinary_error_text_does_not_trigger_stack_trace_detection():
    assert detect_stack_trace(snapshot(status=500, text="An error occurred. Try again.")) == []
