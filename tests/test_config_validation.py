import pytest

from core.config_validation import validate_config


def base_config():
    return {
        "scanner": {
            "scope": {"include_domains": [], "exclude_paths": [], "allowlist": []},
            "crawler": {"max_depth": 2, "max_urls": 20, "max_url_length": 2048},
            "concurrency": {
                "threads": 2,
                "per_host_concurrency": 1,
                "timeout": 5,
                "global_timeout_seconds": 30,
                "delay": 0,
                "max_retries": 0,
            },
            "browser": {},
            "request": {"max_redirects": 3, "max_retries": 0, "follow_redirects": False},
            "output": {"directory": "reports"},
            "max_findings_per_plugin": 20,
        }
    }


def test_invalid_threads_are_rejected_before_scan():
    config = base_config()
    config["scanner"]["concurrency"]["threads"] = 0
    with pytest.raises(ValueError, match="threads"):
        validate_config(config)


def test_unknown_and_deprecated_keys_are_reported():
    config = base_config()
    config["scanner"]["mystery_option"] = True
    config["scanner"]["request"]["user_agent_pool"] = ["x"]
    warnings = validate_config(config)
    assert any("mystery_option" in item for item in warnings)
    assert any("user_agent_pool" in item for item in warnings)
