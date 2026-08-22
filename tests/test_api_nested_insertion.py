from __future__ import annotations

import json

from core.api_engine import APIEngine


class Response:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._payload


class Requester:
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self.scope_policy = None

    def send(self, method, url, **kwargs):
        assert method == "GET"
        assert url == self.url
        return Response(self.payload)


def config():
    return {
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
        },
        "api": {"max_schema_depth": 8, "max_insertion_points": 100},
    }


def test_openapi_local_ref_and_nested_array_become_distinct_insertion_paths():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api/"}],
        "components": {
            "schemas": {
                "UserUpdate": {
                    "type": "object",
                    "required": ["profile"],
                    "properties": {
                        "profile": {
                            "type": "object",
                            "required": ["email"],
                            "properties": {
                                "email": {"type": "string"},
                                "id": {"type": "integer"},
                            },
                        },
                        "reviewer": {
                            "type": "object",
                            "properties": {"id": {"type": "integer"}},
                        },
                        "roles": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "integer"},
                                    "name": {"type": "string"},
                                },
                            },
                        },
                    },
                }
            }
        },
        "paths": {
            "/users/42": {
                "patch": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserUpdate"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert len(surfaces) == 1
    surface = surfaces[0]
    by_path = {item.path: item for item in surface.inputs}
    assert set(by_path) == {
        "/profile/email",
        "/profile/id",
        "/reviewer/id",
        "/roles/0/id",
        "/roles/0/name",
    }
    assert by_path["/profile/email"].required is True
    assert by_path["/roles/0/id"].data_type == "integer"
    assert surface.meta["body_format"] == "json"
    assert surface.meta["input_paths"] == [item.path for item in surface.inputs]
    assert engine.swagger_inventory["insertion_paths_total"] == 5


def test_openapi_insertion_budget_bounds_large_schema():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/bulk": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        f"field_{index}": {"type": "string"}
                                        for index in range(50)
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    cfg = config()
    cfg["api"]["max_insertion_points"] = 7
    engine = APIEngine(cfg, requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert len(surfaces[0].inputs) == 7
    assert engine.swagger_inventory["insertion_paths_total"] == 7
