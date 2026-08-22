from urllib.parse import urlparse

from layers.dns_tls_checks import DNSTLSScanner


def scanner():
    return DNSTLSScanner(
        {"passive_checks": {"dns_tls": {"enabled": True, "timeout": 1}}}
    )


def test_certificate_verification_failure_is_a_finding_not_scanner_error():
    layer = scanner()
    findings = layer._build_tls_findings(
        urlparse("https://example.test"),
        {
            "enabled": True,
            "host": "example.test",
            "port": 443,
            "verified": False,
            "verification_code": 62,
            "verification_error": "Hostname mismatch",
        },
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "TLS Certificate Validation Failed"
    assert finding.verification_status == "detected"
    assert finding.severity == "MEDIUM"
    assert layer.errors == []


def test_valid_tls_inventory_is_kept_informational():
    layer = scanner()
    findings = layer._build_tls_findings(
        urlparse("https://example.test"),
        {
            "enabled": True,
            "host": "example.test",
            "port": 443,
            "verified": True,
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        },
    )
    assert len(findings) == 1
    assert findings[0].type == "TLS Inventory"
    assert findings[0].verification_status == "informational"


def test_plain_http_remains_a_detected_transport_finding():
    layer = scanner()
    findings = layer._build_tls_findings(
        urlparse("http://example.test"),
        {"enabled": False, "reason": "plaintext_http"},
    )
    assert len(findings) == 1
    assert findings[0].type == "HTTPS Not Enabled"
    assert findings[0].verification_status == "detected"
