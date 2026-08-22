from core.scan_profiles import apply_profile
from core.scan_strategies import STRATEGIES, apply_strategy


def _base_config(strategy="balanced"):
    return {
        "scanner": {
            "strategy": strategy,
            "scope": {"max_depth": 2},
            "crawler": {
                "max_depth": 3,
                "max_urls": 2000,
                "javascript_discovery": {},
                "discovery_files": {},
                "site_map": {},
            },
            "browser": {"xss_verification": {}, "interactions": {}},
            "passive_checks": {"web": {}, "data_exposure": {}},
            "active_checks": {"web": {}, "templates": {}, "xml": {}},
            "auth_verification": {},
            "workflows": {},
            "plugins": {
                "sqli": {},
                "business_logic": {"idor": {}},
                "xss_reflected": {},
                "open_redirect": {},
                "lfi": {},
                "cmd_injection": {},
            },
            "request": {},
        }
    }


def test_deep_passive_increases_discovery_without_enabling_active_checks():
    rendered = apply_profile(_base_config("deep"), "passive")["scanner"]

    assert rendered["strategy"] == "deep"
    assert rendered["crawler"]["max_depth"] == 5
    assert rendered["crawler"]["max_urls"] == 10_000
    assert rendered["crawler"]["javascript_discovery"]["max_scripts"] == 50
    assert rendered["crawler"]["discovery_files"]["max_sitemap_urls"] == 5000
    assert rendered["browser_enabled"] is False
    assert rendered["active_checks"]["web"]["enabled"] is False
    assert rendered["active_checks"]["templates"]["enabled"] is False
    assert rendered["active_checks"]["xml"]["enabled"] is False
    assert rendered["plugins"]["sqli"]["enabled"] is False
    assert rendered["plugins"]["lfi"]["enabled"] is False
    assert rendered["plugins"]["cmd_injection"]["enabled"] is False


def test_lightweight_safe_active_preserves_safety_profile():
    rendered = apply_profile(_base_config("lightweight"), "safe-active")["scanner"]

    assert rendered["strategy"] == "lightweight"
    assert rendered["crawler"]["max_depth"] == 1
    assert rendered["crawler"]["max_urls"] == 250
    assert rendered["active_checks"]["web"]["enabled"] is True
    assert rendered["plugins"]["sqli"]["enabled"] is True
    assert rendered["browser_enabled"] is False
    assert rendered["workflows"]["enabled"] is False
    assert rendered["plugins"]["lfi"]["enabled"] is False
    assert rendered["plugins"]["cmd_injection"]["enabled"] is False


def test_apply_strategy_rejects_unknown_strategy():
    try:
        apply_strategy(_base_config(), "maximum")
    except ValueError as exc:
        assert "Unknown scan strategy" in str(exc)
    else:
        raise AssertionError("unknown strategy should fail")


def test_strategy_catalog_is_stable_and_orderable():
    assert set(STRATEGIES) == {"lightweight", "balanced", "deep"}
    assert STRATEGIES["lightweight"]["crawler"]["max_urls"] < STRATEGIES["balanced"]["crawler"]["max_urls"]
    assert STRATEGIES["balanced"]["crawler"]["max_urls"] < STRATEGIES["deep"]["crawler"]["max_urls"]
