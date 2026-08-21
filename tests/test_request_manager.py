import threading
from types import SimpleNamespace

import pytest

from core.request_manager import RequestManager


def make_config(**scope_overrides):
    scope = {
        "include_domains": ["example.com", "*.example.org"],
        "allow_private": False,
        # Unit tests should not depend on external DNS. DNS rebinding behavior
        # is covered directly in test_scope.py.
        "resolve_dns": False,
    }
    scope.update(scope_overrides)
    return {
        "target": "",
        "crawler": {"max_url_length": 2048},
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
            "max_redirects": 3,
        },
        "scope": scope,
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def fake_response(url, *, status=200, headers=None):
    headers = dict(headers or {})
    return SimpleNamespace(
        status_code=status,
        headers=headers,
        text="ok",
        url=url,
        is_redirect=status in {301, 302, 303, 307, 308} and "Location" in headers,
        is_permanent_redirect=status in {301, 308} and "Location" in headers,
    )


def test_scope_allows_exact_and_wildcard_domains():
    manager = RequestManager(make_config())
    assert manager._host_allowed("example.com")
    assert manager._host_allowed("api.example.org")
    assert manager._host_allowed("example.org")
    assert not manager._host_allowed("example.net")
    assert not manager._host_allowed("badexample.org")
    assert not manager._host_allowed("example.org.evil.test")


def test_scope_blocks_private_and_reserved_ip_literals_by_default():
    manager = RequestManager(make_config(include_domains=[]))
    assert not manager._host_allowed("127.0.0.1")
    assert not manager._host_allowed("10.0.0.5")
    assert not manager._host_allowed("169.254.10.1")
    assert not manager._host_allowed("192.0.2.1")


def test_scope_can_explicitly_allow_private_targets():
    manager = RequestManager(
        make_config(include_domains=[], allow_private=True)
    )
    assert manager._host_allowed("127.0.0.1")
    assert manager._host_allowed("10.0.0.5")


def test_send_rejects_non_http_schemes_before_network_call(monkeypatch):
    manager = RequestManager(make_config(include_domains=[]))
    called = False

    def fake_request(**kwargs):
        nonlocal called
        called = True
        return fake_response(kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    with pytest.raises(RuntimeError, match="Unsupported URL scheme"):
        manager.send("GET", "file:///etc/passwd")
    assert called is False


def test_send_honors_per_call_timeout(monkeypatch):
    manager = RequestManager(make_config(include_domains=[]))
    observed = {}

    def fake_request(**kwargs):
        observed.update(kwargs)
        return fake_response(kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    response = manager.send("GET", "https://public.example", timeout=1.25)
    assert response.status_code == 200
    assert observed["timeout"] == 1.25
    # Redirect following is intentionally centralized and manual.
    assert observed["allow_redirects"] is False


def test_session_does_not_trust_environment_credentials():
    manager = RequestManager(make_config(include_domains=[]))
    assert manager.session.trust_env is False


def test_each_worker_thread_gets_its_own_session():
    manager = RequestManager(make_config(include_domains=[]))
    session_ids = []
    lock = threading.Lock()
    barrier = threading.Barrier(3)

    def worker():
        barrier.wait()
        session_id = id(manager.session)
        with lock:
            session_ids.append(session_id)
        barrier.wait()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    main_session_id = id(manager.session)
    barrier.wait()
    for thread in threads:
        thread.join()

    assert len(set(session_ids + [main_session_id])) == 3


def test_scoped_redirect_is_followed_only_after_validation(monkeypatch):
    config = make_config(include_domains=["example.com"])
    config["request"]["follow_redirects"] = True
    manager = RequestManager(config)
    calls = []

    def fake_request(**kwargs):
        calls.append(kwargs["url"])
        if len(calls) == 1:
            return fake_response(
                kwargs["url"],
                status=302,
                headers={"Location": "/next"},
            )
        return fake_response(kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    response = manager.send("GET", "https://example.com/start")
    assert response.url == "https://example.com/next"
    assert calls == ["https://example.com/start", "https://example.com/next"]


def test_off_scope_redirect_is_blocked_before_second_network_call(monkeypatch):
    config = make_config(include_domains=["example.com"])
    config["request"]["follow_redirects"] = True
    manager = RequestManager(config)
    calls = []

    def fake_request(**kwargs):
        calls.append(kwargs["url"])
        return fake_response(
            kwargs["url"],
            status=302,
            headers={"Location": "https://evil.test/landing"},
        )

    monkeypatch.setattr(manager.session, "request", fake_request)
    with pytest.raises(RuntimeError, match="scope policy"):
        manager.send("GET", "https://example.com/start")
    assert calls == ["https://example.com/start"]


def test_retry_after_supports_seconds_and_invalid_values():
    assert RequestManager._retry_after_seconds("7", 1) == 7
    assert RequestManager._retry_after_seconds("not-a-date", 3) == 3
