from __future__ import annotations

from core.models import AttackSurface, InputField
from core.plugin_request import send_plugin_test
from plugins.base import TestCase


class Requester:
    def __init__(self):
        self.calls = []
        self.config = {"auth": {"headers": {}}}
        self.cookies = {}
        self.timeout = 5

    def send_as_actor(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return object()


def test_nested_json_plugin_mutates_only_selected_pointer():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/users/42",
        method="PATCH",
        inputs=[
            InputField(name="id", value=7, kind="body", path="/owner/id", data_type="integer"),
            InputField(name="id", value=9, kind="body", path="/reviewer/id", data_type="integer"),
            InputField(name="email", value="a@example.test", kind="body", path="/reviewer/email"),
        ],
        source="swagger",
        meta={"content_type": "application/json", "nested_active_supported": True},
    )
    testcase = TestCase(
        plugin="sqli",
        surface_id=surface.id,
        param="id",
        kind="body",
        input_path="/reviewer/id",
        payload="CANARY",
    )

    send_plugin_test(requester, surface, testcase)

    method, url, kwargs = requester.calls[0]
    assert method == "PATCH"
    assert url == surface.url
    assert kwargs["data"] is None
    assert kwargs["json"] == {
        "owner": {"id": 7},
        "reviewer": {"id": "CANARY", "email": "a@example.test"},
    }


def test_nested_json_candidate_requires_canonical_path_when_leaf_is_ambiguous():
    requester = Requester()
    surface = AttackSurface(
        url="https://example.test/users/42",
        method="PATCH",
        inputs=[
            InputField(name="id", value=7, kind="body", path="/owner/id"),
            InputField(name="id", value=9, kind="body", path="/reviewer/id"),
        ],
        source="swagger",
        meta={"content_type": "application/json", "nested_active_supported": True},
    )
    testcase = TestCase(
        plugin="sqli",
        surface_id=surface.id,
        param="id",
        kind="body",
        payload="CANARY",
    )

    try:
        send_plugin_test(requester, surface, testcase)
    except ValueError as exc:
        assert "ambiguous" in str(exc).lower()
    else:
        raise AssertionError("ambiguous nested fields must not be mutated by leaf name")
