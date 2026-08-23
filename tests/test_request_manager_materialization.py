from __future__ import annotations

from core.models import AttackSurface, InputField
from core.request_manager import RequestManager


def _manager_capture():
    manager = object.__new__(RequestManager)
    manager.config = {"auth": {"headers": {"X-Scanner": "1"}}}
    manager.cookies = {"scanner": "cookie"}
    manager.timeout = 7
    manager.calls = []

    def capture(method, url, **kwargs):
        manager.calls.append((method, url, kwargs))
        return object()

    manager.send_as_actor = capture
    return manager


def _surface():
    return AttackSurface(
        url="https://example.com/api/users",
        method="POST",
        params={"mode": "edit"},
        inputs=[
            InputField(name="mode", value="edit", kind="query", path="mode"),
            InputField(name="id", value=7, kind="body", path="/owner/id", data_type="integer"),
            InputField(name="id", value=11, kind="body", path="/reviewer/id", data_type="integer"),
            InputField(name="enabled", value=False, kind="body", path="/settings/enabled", data_type="boolean"),
            InputField(name="count", value=0, kind="body", path="/settings/count", data_type="integer"),
        ],
        source="openapi",
        meta={"content_type": "application/json", "body_format": "json"},
    )


def test_send_surface_baseline_uses_nested_json_and_post_query():
    manager = _manager_capture()
    surface = _surface()

    manager.send_surface(surface)

    method, url, kwargs = manager.calls[-1]
    assert method == "POST"
    assert url == surface.url
    assert kwargs["params"] == {"mode": "edit"}
    assert kwargs["data"] is None
    assert kwargs["json"] == {
        "owner": {"id": 7},
        "reviewer": {"id": 11},
        "settings": {"enabled": False, "count": 0},
    }
    assert kwargs["headers"] == {"X-Scanner": "1"}
    assert kwargs["cookies"] == {"scanner": "cookie"}
    assert kwargs["timeout"] == 7


def test_send_surface_flat_body_injection_still_works():
    manager = _manager_capture()
    surface = AttackSurface(
        url="https://example.com/login",
        method="POST",
        inputs=[InputField(name="username", value="alice", kind="body", path="username")],
        source="form",
        meta={"content_type": "application/x-www-form-urlencoded"},
    )

    manager.send_surface(surface, "username", "bob")

    _method, _url, kwargs = manager.calls[-1]
    assert kwargs["data"] == {"username": "bob"}
    assert kwargs["json"] is None


def test_send_surface_rejects_ambiguous_duplicate_body_name_injection():
    manager = _manager_capture()
    surface = _surface()

    try:
        manager.send_surface(surface, "id", "probe")
    except ValueError as exc:
        assert "ambiguous" in str(exc).lower()
    else:
        raise AssertionError("ambiguous nested body injection must be rejected")
