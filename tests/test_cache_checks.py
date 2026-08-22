from layers.cache_checks import check_cache_policy


def snapshot(**overrides):
    data = {
        "url": "https://example.test/account",
        "path": "/account",
        "status": 200,
        "headers": {"cache-control": "public, max-age=300"},
        "set_cookies": ["session=abc; Path=/; Secure; HttpOnly"],
    }
    data.update(overrides)
    return data


def test_explicit_public_cache_on_session_response_is_reported():
    findings = check_cache_policy(snapshot())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Sensitive Response Cache Policy"
    assert finding.verification_status == "suspected"
    assert finding.severity == "MEDIUM"


def test_private_or_no_store_policy_is_not_reported():
    assert check_cache_policy(
        snapshot(headers={"cache-control": "private, max-age=300"})
    ) == []
    assert check_cache_policy(
        snapshot(headers={"cache-control": "no-store"})
    ) == []


def test_missing_cache_control_is_not_reported_by_itself():
    assert check_cache_policy(snapshot(headers={})) == []


def test_public_cache_on_non_sensitive_static_page_is_not_reported():
    assert check_cache_policy(
        snapshot(
            url="https://example.test/assets/app.js",
            path="/assets/app.js",
            set_cookies=[],
        )
    ) == []
