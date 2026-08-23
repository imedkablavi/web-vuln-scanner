import json

from layers.data_exposure import DataExposureScanner


class NoopRequester:
    pass


def test_sensitive_indicator_never_stores_raw_secret():
    secret = "SUPERSECRET-7f918-data-exposure"
    scanner = DataExposureScanner(
        NoopRequester(),
        {"passive_checks": {"data_exposure": {"enabled": True}}},
    )
    findings = scanner._check_sensitive_indicators(
        {
            "status": 200,
            "text": f"DB_PASSWORD={secret}\nDEBUG=true",
            "path": "/.env",
            "url": "https://example.test/.env",
        }
    )
    assert findings
    persisted = json.dumps(findings[0].evidence)
    assert secret not in persisted
    assert "***redacted***" in persisted
    assert "match_sha256" in persisted
