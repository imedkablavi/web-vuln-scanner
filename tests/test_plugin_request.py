from __future__ import annotations

from core.models import AttackSurface, InputField
from core.plugin_request import send_plugin_test
from plugins.base import TestCase


class Requester:
    def __init__(self):
        self.config = {"auth": {"headers": {"X-Base": "1"}}}
        self.cookies = {"session": "base"}
        self.timeout = 7
        self.calls = []

    def send_as_actor(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return object()


def testcase(kind, param="probe", payload="PAYLOAD", **kwargs):
    return TestCase(
        plugin="fixture",
        surface_id="surface",
        param=param,
        kind=kind,
        payload=payload,
        **kwargs,
    )


def test_query_injection_preserves_other_parameters():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/search",
        method="GET",
        params={"probe": "old", "lang": "en"},
    )
    send_plugin_test(requester, surface, testcase("query"))

    method, _url, kwargs = requester.calls[-1]
    assert method == "GET"
    assert kwargs["params"] == {"probe": "PAYLOAD", "lang": "en"}
    assert kwargs["headers"]["X-Base"] == "1"
    assert kwargs["cookies"]["session"] == "base"


def test_body_injection_uses_json_for_json_surface():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/api/item",
        method="POST",
        inputs=[
            InputField("probe", "old", "body"),
            InputField("keep", "value", "body"),
        ],
        meta={"content_type": "application/json"},
    )
    send_plugin_test(requester, surface, testcase("body"))

    method, _url, kwargs = requester.calls[-1]
    assert method == "POST"
    assert kwargs["json"] == {"probe": "PAYLOAD", "keep": "value"}
    assert kwargs["data"] is None


def test_header_and_cookie_injection_target_the_declared_kind():
    requester = Requester()
    header_surface = AttackSurface(
        url="https://example.test/",
        method="GET",
        inputs=[InputField("X-Test", "old", "header")],
    )
    send_plugin_test(
        requester,
        header_surface,
        testcase("header", param="X-Test"),
    )
    assert requester.calls[-1][2]["headers"]["X-Test"] == "PAYLOAD"

    cookie_surface = AttackSurface(
        url="https://example.test/",
        method="GET",
        inputs=[InputField("pref", "old", "cookie")],
    )
    send_plugin_test(
        requester,
        cookie_surface,
        testcase("cookie", param="pref"),
    )
    assert requester.calls[-1][2]["cookies"]["pref"] == "PAYLOAD"


def test_method_override_and_redirect_policy_are_forwarded():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/resource",
        method="GET",
        inputs=[InputField("probe", "old", "body")],
    )
    send_plugin_test(
        requester,
        surface,
        testcase(
            "body",
            method_override="PATCH",
            allow_redirects=False,
        ),
    )
    method, _url, kwargs = requester.calls[-1]
    assert method == "PATCH"
    assert kwargs["allow_redirects"] is False
    assert kwargs["data"]["probe"] == "PAYLOAD"


def test_path_injection_replaces_discovered_segment_only():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/users/123/profile?view=full",
        method="GET",
        inputs=[InputField("user_id", "123", "path")],
    )
    send_plugin_test(
        requester,
        surface,
        testcase("path", param="user_id", payload="a/b"),
    )
    _method, url, _kwargs = requester.calls[-1]
    assert url == "https://example.test/users/a%2Fb/profile?view=full"


def test_unknown_input_kind_is_rejected_before_request():
    requester = Requester()
    surface = AttackSurface(url="https://example.test/", method="GET")
    try:
        send_plugin_test(requester, surface, testcase("unknown"))
    except ValueError as exc:
        assert "Unsupported plugin input kind" in str(exc)
    else:
        raise AssertionError("unknown input kind should be rejected")
    assert requester.calls == []
