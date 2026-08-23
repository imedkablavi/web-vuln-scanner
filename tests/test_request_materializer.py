from __future__ import annotations

import pytest

from core.models import AttackSurface, InputField
from core.plugin_request import send_plugin_test
from core.request_materializer import materialize_surface_request
from plugins.base import TestCase


def _nested_surface(content_type="application/json"):
    return AttackSurface(
        url="https://example.com/api/users?mode=edit",
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
        meta={"content_type": content_type, "body_format": "json", "active_eligible": True},
    )


def test_materializer_reconstructs_nested_json_and_keeps_post_query_values():
    materialized = materialize_surface_request(_nested_surface())

    assert materialized.method == "POST"
    assert materialized.params == {"mode": "edit"}
    assert materialized.data is None
    assert materialized.json == {
        "owner": {"id": 7},
        "reviewer": {"id": 11},
        "settings": {"enabled": False, "count": 0},
    }


def test_materializer_mutates_only_selected_json_pointer():
    materialized = materialize_surface_request(
        _nested_surface(),
        body_mutation_name="id",
        body_mutation_path="/owner/id",
        body_mutation_payload="'",
        mutate_body=True,
    )

    assert materialized.json["owner"]["id"] == "'"
    assert materialized.json["reviewer"]["id"] == 11
    assert materialized.json["settings"] == {"enabled": False, "count": 0}


def test_vendor_json_content_type_uses_json_materialization():
    materialized = materialize_surface_request(
        _nested_surface("application/problem+json; charset=utf-8")
    )
    assert materialized.data is None
    assert materialized.json["owner"]["id"] == 7


def test_non_json_nested_mutation_is_rejected():
    surface = _nested_surface("application/x-www-form-urlencoded")
    with pytest.raises(ValueError, match="requires a JSON content type"):
        materialize_surface_request(
            surface,
            body_mutation_name="id",
            body_mutation_path="/owner/id",
            body_mutation_payload="probe",
            mutate_body=True,
        )


class _CaptureRequester:
    timeout = 3
    cookies = {"scanner": "cookie"}
    config = {"auth": {"headers": {"X-Scanner": "1"}}}

    def __init__(self):
        self.calls = []

    def send_as_actor(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return object()


def test_plugin_probe_uses_same_nested_shape_and_keeps_query_on_post():
    requester = _CaptureRequester()
    surface = _nested_surface()
    testcase = TestCase(
        plugin="sqli",
        surface_id=surface.id,
        param="id",
        kind="body",
        payload="'",
        input_path="/owner/id",
    )

    send_plugin_test(requester, surface, testcase)

    method, url, kwargs = requester.calls[-1]
    assert method == "POST"
    assert url == surface.url
    assert kwargs["params"] == {"mode": "edit"}
    assert kwargs["data"] is None
    assert kwargs["json"] == {
        "owner": {"id": "'"},
        "reviewer": {"id": 11},
        "settings": {"enabled": False, "count": 0},
    }
    assert kwargs["headers"] == {"X-Scanner": "1"}
    assert kwargs["cookies"] == {"scanner": "cookie"}
