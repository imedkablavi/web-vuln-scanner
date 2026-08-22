from pathlib import Path
from urllib.parse import urlsplit

import pytest

from core.scope import ScopePolicy
from layers.safe_template_checks import (
    SafeTemplateScanner,
    TemplateValidationError,
    validate_safe_template,
)


class Response:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class Requester:
    def __init__(self, config, responses=None):
        self.scope_policy = ScopePolicy(config)
        self.responses = responses or {}
        self.calls = []

    def send(self, method, url, allow_redirects=False):
        self.calls.append((method, url, allow_redirects))
        path = urlsplit(url).path
        return self.responses.get(path, Response(status=404, text="not found"))


def config(*, enabled=True, include_builtin=False, files=None, max_requests=25, exclude_paths=None):
    return {
        "target": "https://example.test/app",
        "scope": {
            "include_domains": ["example.test"],
            "exclude_paths": exclude_paths or [],
            "allow_private": False,
            "resolve_dns": False,
        },
        "crawler": {"max_url_length": 2048},
        "concurrency": {"global_timeout_seconds": 30},
        "active_checks": {
            "templates": {
                "enabled": enabled,
                "include_builtin": include_builtin,
                "directory": "",
                "files": [str(item) for item in (files or [])],
                "max_templates": 25,
                "max_requests": max_requests,
                "max_body_bytes": 4096,
            }
        },
    }


def write_template(path: Path, text: str):
    path.write_text(text, encoding="utf-8")
    return path


def test_template_schema_rejects_unsafe_methods_origins_and_dsl():
    base = {
        "id": "fixture",
        "info": {
            "name": "Fixture",
            "severity": "low",
            "confidence": "high",
            "remediation": "Fix it.",
        },
        "request": {"method": "GET", "path": "/health"},
        "matchers": [{"type": "status", "values": [200]}],
    }
    assert validate_safe_template(base)["request"]["method"] == "GET"

    post = {**base, "request": {"method": "POST", "path": "/health"}}
    with pytest.raises(TemplateValidationError, match="GET or HEAD"):
        validate_safe_template(post)

    external = {**base, "request": {"method": "GET", "path": "//evil.test/x"}}
    with pytest.raises(TemplateValidationError, match="same-origin"):
        validate_safe_template(external)

    dsl = {**base, "request": {"method": "GET", "path": "/{{BaseURL}}"}}
    with pytest.raises(TemplateValidationError, match="variables and DSL"):
        validate_safe_template(dsl)


def test_template_match_requires_all_matchers_and_persists_no_body(tmp_path):
    template = write_template(
        tmp_path / "fixture.yaml",
        """
id: fixture-exposure
info:
  name: Fixture Exposure
  severity: medium
  confidence: high
  category: information-disclosure
  remediation: Restrict the endpoint.
request:
  method: GET
  path: /debug
matchers_condition: all
matchers:
  - type: status
    values: [200]
  - type: header
    name: Content-Type
    values: [application/json]
  - type: word
    part: body
    condition: all
    values: [debug_marker, runtime_marker]
""",
    )
    body = "debug_marker runtime_marker secret-body-value"
    cfg = config(files=[template])
    requester = Requester(
        cfg,
        {"/debug": Response(200, body, {"Content-Type": "application/json; charset=utf-8"})},
    )

    findings, meta = SafeTemplateScanner(requester, cfg).scan(cfg["target"])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "fixture-exposure"
    assert finding.verification_status == "detected"
    assert finding.evidence["matcher_types"] == ["status", "header", "word"]
    assert "secret-body-value" not in repr(finding.evidence)
    assert requester.calls == [("GET", "https://example.test/debug", False)]
    assert meta["executed_requests"] == 1
    assert meta["matched_templates"] == 1
    assert meta["raw_http"] is False
    assert meta["dsl"] is False
    assert meta["redirects_followed"] is False


def test_template_request_budget_is_hard_limit(tmp_path):
    first = write_template(
        tmp_path / "a.yaml",
        """
id: a
info: {name: A, severity: low, confidence: high, remediation: Fix A.}
request: {method: GET, path: /a}
matchers: [{type: status, values: [200]}]
""",
    )
    second = write_template(
        tmp_path / "b.yaml",
        """
id: b
info: {name: B, severity: low, confidence: high, remediation: Fix B.}
request: {method: GET, path: /b}
matchers: [{type: status, values: [200]}]
""",
    )
    cfg = config(files=[first, second], max_requests=1)
    requester = Requester(cfg, {"/a": Response(200), "/b": Response(200)})

    findings, meta = SafeTemplateScanner(requester, cfg).scan(cfg["target"])
    assert len(requester.calls) == 1
    assert len(findings) == 1
    assert meta["executed_requests"] == 1
    assert any("Stopped after 1" in item for item in meta["skipped"])


def test_template_scope_exclusions_are_enforced_before_request(tmp_path):
    template = write_template(
        tmp_path / "admin.yaml",
        """
id: admin-fixture
info: {name: Admin, severity: low, confidence: high, remediation: Restrict it.}
request: {method: GET, path: /admin/status}
matchers: [{type: status, values: [200]}]
""",
    )
    cfg = config(files=[template], exclude_paths=["/admin"])
    requester = Requester(cfg, {"/admin/status": Response(200)})

    findings, meta = SafeTemplateScanner(requester, cfg).scan(cfg["target"])
    assert findings == []
    assert requester.calls == []
    assert meta["errors"][0]["kind"] == "template_scope"


def test_invalid_custom_template_is_reported_not_executed(tmp_path):
    template = write_template(
        tmp_path / "unsafe.yaml",
        """
id: unsafe
info: {name: Unsafe, severity: high, confidence: high, remediation: Do not run.}
request: {method: DELETE, path: /account}
matchers: [{type: status, values: [200]}]
""",
    )
    cfg = config(files=[template])
    requester = Requester(cfg)
    findings, meta = SafeTemplateScanner(requester, cfg).scan(cfg["target"])
    assert findings == []
    assert requester.calls == []
    assert meta["loaded_templates"] == 0
    assert meta["errors"][0]["kind"] == "template_validation"


def test_builtin_templates_load_and_remain_bounded_get_checks():
    cfg = config(include_builtin=True, max_requests=10)
    requester = Requester(cfg)
    scanner = SafeTemplateScanner(requester, cfg)
    findings, meta = scanner.scan(cfg["target"])

    assert findings == []
    assert meta["loaded_templates"] >= 4
    assert meta["executed_requests"] == meta["loaded_templates"]
    assert all(call[0] in {"GET", "HEAD"} for call in requester.calls)
    assert all(call[2] is False for call in requester.calls)
    assert all(url.startswith("https://example.test/") for _method, url, _redirects in requester.calls)
