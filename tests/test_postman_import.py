from __future__ import annotations

import json

from core.postman_import import _surface_dict, import_postman_data


def collection(secret="SUPER-SECRET-SENTINEL"):
    return {
        "info": {
            "name": "Demo API",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "baseUrl", "value": "https://evil.example.invalid"},
            {"key": "apiKey", "value": secret},
        ],
        "item": [
            {
                "name": "Nested update",
                "request": {
                    "method": "PATCH",
                    "header": [
                        {"key": "Authorization", "value": f"Bearer {secret}"},
                        {"key": "X-Request-ID", "value": secret},
                        {"key": "Content-Type", "value": "application/json"},
                    ],
                    "url": {
                        "raw": "{{baseUrl}}/users/42?expand=profile&token=" + secret,
                        "query": [
                            {"key": "expand", "value": "profile"},
                            {"key": "token", "value": secret},
                        ],
                    },
                    "body": {
                        "mode": "raw",
                        "raw": json.dumps(
                            {
                                "profile": {"email": secret},
                                "owner": {"id": 7},
                                "reviewer": {"id": 9},
                            }
                        ),
                        "options": {"raw": {"language": "json"}},
                    },
                },
            },
            {
                "name": "Out of scope",
                "request": {
                    "method": "GET",
                    "url": "https://outside.example.invalid/admin?id=1",
                },
            },
        ],
    }


def test_postman_import_is_scoped_sanitized_and_nested():
    secret = "SUPER-SECRET-SENTINEL"
    surfaces, summary = import_postman_data(
        collection(secret),
        target="https://example.test/api",
        active_tests=True,
        allow_state_changing_methods=False,
    )

    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface.url == "https://example.test/users/42"
    assert surface.method == "PATCH"
    assert surface.source == "postman"
    assert surface.meta["active_eligible"] is False
    assert surface.meta["body_format"] == "json"
    assert "Authorization" not in surface.meta["observed_header_names"]
    assert "X-Request-ID" in surface.meta["observed_header_names"]
    assert set(surface.params) == {"expand", "token"}

    by_path = {item.path: item for item in surface.inputs if item.kind == "body"}
    assert "/profile/email" in by_path
    assert "/owner/id" in by_path
    assert "/reviewer/id" in by_path
    assert by_path["/profile/email"].value == "TEST_VALUE"
    assert by_path["/owner/id"].value == 1

    rendered = json.dumps(_surface_dict(surface), sort_keys=True)
    assert secret not in rendered
    assert "evil.example.invalid" not in rendered
    assert summary["skipped"]["out_of_scope"] == 1
    assert summary["replayed_requests"] == 0
    assert summary["sanitized"] is True


def test_postman_get_can_be_active_eligible_only_when_explicitly_requested():
    data = {
        "info": {"name": "GET collection"},
        "item": [
            {
                "name": "search",
                "request": {
                    "method": "GET",
                    "url": "https://example.test/search?q=demo",
                },
            }
        ],
    }
    passive, _ = import_postman_data(data, target="https://example.test", active_tests=False)
    active, _ = import_postman_data(data, target="https://example.test", active_tests=True)
    assert passive[0].meta["active_eligible"] is False
    assert active[0].meta["active_eligible"] is True


def test_postman_graphql_variables_are_inventory_only():
    data = {
        "info": {"name": "GraphQL"},
        "item": [
            {
                "name": "query",
                "request": {
                    "method": "POST",
                    "url": "https://example.test/graphql",
                    "body": {
                        "mode": "graphql",
                        "graphql": {
                            "query": "query User($id: ID!) { user(id: $id) { id } }",
                            "variables": json.dumps({"id": "REAL-ID"}),
                        },
                    },
                },
            }
        ],
    }
    surfaces, _ = import_postman_data(
        data,
        target="https://example.test",
        active_tests=True,
        allow_state_changing_methods=True,
    )
    surface = surfaces[0]
    assert surface.meta["active_eligible"] is False
    assert any(item.path == "/variables/id" for item in surface.inputs)
    assert all(item.value != "REAL-ID" for item in surface.inputs)


def test_delete_is_never_active_eligible_from_collection_import():
    data = {
        "info": {"name": "Delete"},
        "item": [
            {
                "request": {
                    "method": "DELETE",
                    "url": "https://example.test/items/42",
                }
            }
        ],
    }
    surfaces, _ = import_postman_data(
        data,
        target="https://example.test",
        active_tests=True,
        allow_state_changing_methods=True,
    )
    assert surfaces[0].meta["active_eligible"] is False
