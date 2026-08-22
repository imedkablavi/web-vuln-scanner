from __future__ import annotations

import json

from core.api_engine import APIEngine


class Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._payload


class Requester:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.scope_policy = None

    def send(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        key = (method.upper(), url)
        return self.responses[key]


def config():
    return {
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
        }
    }


def test_openapi3_discovers_path_query_and_json_body_inputs():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "/api/"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "example": 42},
                        },
                        {
                            "name": "expand",
                            "in": "query",
                            "schema": {"type": "string", "default": "profile"},
                        },
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/items": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "example": "demo"},
                                        "count": {"type": "integer"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "created"}},
                }
            },
        },
    }
    requester = Requester({("GET", spec_url): Response(spec)})
    engine = APIEngine(config(), requester=requester)

    surfaces = engine.load_swagger(spec_url)

    assert len(surfaces) == 2
    get_surface = next(surface for surface in surfaces if surface.method == "GET")
    post_surface = next(surface for surface in surfaces if surface.method == "POST")

    assert get_surface.url == "https://example.test/api/users/42"
    assert get_surface.params["expand"] == "profile"
    assert {(item.name, item.kind) for item in get_surface.inputs} >= {
        ("id", "path"),
        ("expand", "query"),
    }
    assert post_surface.url == "https://example.test/api/items"
    assert post_surface.meta["content_type"] == "application/json"
    assert {item.name for item in post_surface.inputs if item.kind == "body"} == {
        "name",
        "count",
    }
    assert engine.swagger_inventory["input_locations"]["body"] == 2
    assert engine.swagger_inventory["surfaces_with_inputs"] == 2


def test_graphql_inventory_extracts_root_fields_and_arguments():
    endpoint = "https://example.test/graphql"
    payload = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query", "kind": "OBJECT"},
                    {"name": "Mutation", "kind": "OBJECT"},
                ],
                "queryType": {
                    "name": "Query",
                    "fields": [
                        {
                            "name": "user",
                            "args": [
                                {
                                    "name": "id",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": None,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "ID",
                                        },
                                    },
                                }
                            ],
                        }
                    ],
                },
                "mutationType": {
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "updateProfile",
                            "args": [
                                {
                                    "name": "name",
                                    "type": {"kind": "SCALAR", "name": "String"},
                                }
                            ],
                        }
                    ],
                },
            }
        }
    }
    requester = Requester({("POST", endpoint): Response(payload)})
    engine = APIEngine(config(), requester=requester)

    surfaces = engine.scan_graphql(endpoint)

    assert len(surfaces) == 1
    inventory = engine.graphql_inventory
    assert inventory["query_fields_total"] == 1
    assert inventory["mutation_fields_total"] == 1
    assert inventory["query_fields"][0]["name"] == "user"
    assert inventory["query_fields"][0]["args"][0]["type"] == "ID"
    assert inventory["mutation_fields"][0]["name"] == "updateProfile"
    method, url, kwargs = requester.calls[0]
    assert method == "POST"
    assert url == endpoint
    assert kwargs["allow_redirects"] is False
    assert kwargs["source"] == "graphql-discovery"
