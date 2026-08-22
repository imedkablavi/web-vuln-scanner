from core.request_manager import RequestManager


def make_config():
    return {
        "target": "",
        "crawler": {"max_url_length": 2048},
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 5,
            "threads": 2,
            "per_host_concurrency": 2,
        },
        "request": {
            "timeouts": {"connect": 2, "read": 4},
            "max_retries": 0,
            "follow_redirects": False,
            "max_redirects": 3,
        },
        "scope": {"include_domains": [], "allow_private": False, "resolve_dns": False},
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def test_actor_sessions_are_isolated_within_same_worker_thread():
    manager = RequestManager(make_config())
    actor_a = manager._session_for("actor-a")
    actor_b = manager._session_for("actor-b")
    anonymous = manager.session

    actor_a.cookies.set("only_a", "secret-a", domain="example.test", path="/")
    actor_b.cookies.set("only_b", "secret-b", domain="example.test", path="/")

    assert actor_a is manager._session_for("actor-a")
    assert actor_b is manager._session_for("actor-b")
    assert actor_a is not actor_b
    assert actor_a is not anonymous
    assert actor_b is not anonymous
    assert actor_b.cookies.get("only_a") is None
    assert actor_a.cookies.get("only_b") is None
    assert anonymous.cookies.get("only_a") is None
    assert anonymous.cookies.get("only_b") is None


def test_actor_session_does_not_trust_environment_credentials():
    manager = RequestManager(make_config())
    assert manager._session_for("actor-a").trust_env is False
    assert manager._session_for("actor-b").trust_env is False
