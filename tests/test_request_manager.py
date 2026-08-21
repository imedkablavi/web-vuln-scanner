from types import SimpleNamespace

import pytest

from core.request_manager import RequestManager


def make_config(**scope_overrides):
    scope = {
        "include_domains": ["example.com", "*.example.org"],
        "allow_private": False,
    }
    scope.update(scope_overrides)
    return {
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 5,
            "threads": 2,
            "per_host_concurrency": 1,
        },
        "request": {
            "timeouts": {"connect": 2, "read": 4},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "scope": scope,
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def test_scope_allows_exact_and_wildcard_domains():
    manager = RequestManager(make_config())
    assert manager._host_allowed("example.com")
    assert manager._host_allowed("api.example.org")
    assert manager._host_allowed("example.org")
    assert not manager._host_allowed("example.net")
    assert not manager._host_allowed("badexample.org")


def test_scope_blocks_private_and_reserved_ip_literals_by_default():
    manager = RequestManager(make_config(include_domains=[]))
    assert not manager._host_allowed("127.0.0.1")
    assert not manager._host_allowed("10.0.0.5")
    assert not manager._host_allowed("169.254.10.1")
    assert not manager._host_allowed("192.0.2.1")


def test_scope_can_explicitly_allow_private_targets():
    manager = RequestManager(make_config(include_domains=[], allow_private=True))
    assert manager._host_allowed("127.0.0.1")
    assert manager._host_allowed("10.0.0.5")


def test_send_rejects_non_http_schemes_before_network_call(monkeypatch):
    manager = RequestManager(make_config(include_domains=[]))
    called = False

    def fake_request(**kwargs):
        nonlocal called
        called = True
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    with pytest.raises(RuntimeError, match="Unsupported URL scheme"):
        manager.send("GET", "file:///etc/passwd")
    assert called is False


def test_send_honors_per_call_timeout(monkeypatch):
    manager = RequestManager(make_config(include_domains=[]))
    observed = {}

    def fake_request(**kwargs):
        observed.update(kwargs)
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    response = manager.send("GET", "https://public.example", timeout=1.25)
    assert response.status_code == 200
    assert observed["timeout"] == 1.25


def test_retry_after_supports_seconds_and_invalid_values():
    assert RequestManager._retry_after_seconds("7", 1) == 7
    assert RequestManager._retry_after_seconds("not-a-date", 3) == 3
