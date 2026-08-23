from __future__ import annotations

from core.request_manager import RequestManager


def _config():
    return {
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 1,
            "threads": 1,
            "per_host_concurrency": 1,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "scope": {
            "include_domains": ["127.0.0.1:8080"],
            "allow_private": True,
        },
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def test_allow_private_does_not_bypass_explicit_include_domains():
    manager = RequestManager(_config())

    assert manager._host_allowed("127.0.0.1", "127.0.0.1:8080") is True
    assert manager._host_allowed("127.0.0.1", "127.0.0.1:9090") is False
    assert manager._host_allowed("10.0.0.5", "10.0.0.5") is False


def test_private_target_is_denied_when_allow_private_is_false():
    config = _config()
    config["scope"]["allow_private"] = False
    manager = RequestManager(config)

    assert manager._host_allowed("127.0.0.1", "127.0.0.1:8080") is False
