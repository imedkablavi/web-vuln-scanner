from types import SimpleNamespace

from layers.api_checks import APIPostureScanner
from layers.dns_tls_checks import DNSTLSScanner
from layers.web_checks import WebPostureScanner


class NoopRequester:
    def send(self, *args, **kwargs):
        raise AssertionError("network should not be used by this unit fixture")


def test_web_headers_missing_are_detected_with_bounded_evidence():
    scanner = WebPostureScanner(NoopRequester(), {"passive_checks": {"web": {}}})
    findings = scanner._check_security_headers(
        {
            "headers": {"content-type": "text/html"},
            "content_type": "text/html",
            "url": "https://example.test/",
            "status": 200,
            "host": "example.test",
            "path": "/",
        }
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Missing Security Headers"
    assert finding.verification_status == "detected"
    assert "Content-Security-Policy" in finding.evidence["missing_headers"]
    assert "Strict-Transport-Security" in finding.evidence["missing_headers"]


def test_web_headers_complete_do_not_produce_finding():
    scanner = WebPostureScanner(NoopRequester(), {"passive_checks": {"web": {}}})
    findings = scanner._check_security_headers(
        {
            "headers": {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "strict-transport-security": "max-age=31536000",
            },
            "content_type": "text/html",
            "url": "https://example.test/",
            "status": 200,
            "host": "example.test",
            "path": "/",
        }
    )
    assert findings == []


def test_web_verbose_error_requires_server_error_status():
    scanner = WebPostureScanner(NoopRequester(), {"passive_checks": {"web": {}}})
    snapshot = {
        "text": "Traceback (most recent call last): SQLSTATE syntax error",
        "status": 500,
        "url": "https://example.test/error",
        "host": "example.test",
        "path": "/error",
    }
    findings = scanner._check_verbose_errors(snapshot)
    assert len(findings) == 1
    assert findings[0].type == "Verbose Error Disclosure"
    snapshot["status"] = 200
    assert scanner._check_verbose_errors(snapshot) == []


def test_dns_tls_plain_http_produces_inventory_and_https_observation():
    scanner = DNSTLSScanner({"passive_checks": {"dns_tls": {"enabled": True}}})
    findings, meta = scanner.scan("http://127.0.0.1:8080")
    types = {finding.type for finding in findings}
    assert "Literal IP Scope" in types
    assert "HTTPS Not Enabled" in types
    assert meta["dns_inventory"]["mode"] == "literal_ip"
    assert meta["tls_inventory"]["reason"] == "plaintext_http"


def test_dns_tls_disabled_is_explicitly_skipped():
    scanner = DNSTLSScanner({"passive_checks": {"dns_tls": {"enabled": False}}})
    findings, meta = scanner.scan("https://example.test")
    assert findings == []
    assert meta["skipped"]


def test_api_posture_builds_swagger_and_graphql_findings():
    engine = SimpleNamespace(
        swagger_inventory={
            "url": "https://example.test/openapi.json",
            "spec_version": "3.1.0",
            "base_url": "https://example.test/",
            "paths_total": 3,
            "operations_total": 4,
            "operations_without_security": [
                {"method": "GET", "path": "/internal", "summary": "internal"}
            ],
        },
        graphql_inventory={
            "url": "https://example.test/graphql",
            "status": 200,
            "introspection_enabled": True,
            "types_total": 12,
            "query": "query { __schema { types { name } } }",
        },
        errors=[],
    )
    scanner = APIPostureScanner({"passive_checks": {"api": {"enabled": True}}})
    findings, meta = scanner.scan(engine)
    types = {finding.type for finding in findings}
    assert "OpenAPI Surface Inventory" in types
    assert "Undeclared API Security Requirements" in types
    assert "GraphQL Introspection Enabled" in types
    assert meta["swagger_inventory"]["operations_total"] == 4


def test_api_posture_disabled_returns_no_findings():
    engine = SimpleNamespace(swagger_inventory={}, graphql_inventory={}, errors=[])
    scanner = APIPostureScanner({"passive_checks": {"api": {"enabled": False}}})
    findings, meta = scanner.scan(engine)
    assert findings == []
    assert meta["skipped"]
