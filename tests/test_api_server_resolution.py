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
    def __init__(self, url, payload, scope_policy=None):
        self.url = url
        self.payload = payload
        self.scope_policy = scope_policy

    def send(self, method, url, **kwargs):
        assert method == "GET"
        assert url == self.url
        return Response(self.payload)


def config():
    return {
        "target": "https://example.test",
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
        },
        "api": {"max_schema_depth": 8, "max_insertion_points": 100},
        "crawler": {"max_url_length": 4096},
        "concurrency": {"global_timeout_seconds": 60},
    }


def test_missing_servers_uses_origin_root_not_spec_file_path():
    spec_url = "https://example.test/specs/openapi.json"
    spec = {
        "openapi": "3.1.2",
        "paths": {
            "/pets": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert [surface.url for surface in surfaces] == ["https://example.test/pets"]
    assert engine.swagger_inventory["base_url"] == "https://example.test/"


def test_operation_server_overrides_path_and_root_servers():
    spec_url = "https://example.test/specs/openapi.json"
    spec = {
        "openapi": "3.1.2",
        "servers": [{"url": "/v1"}],
        "paths": {
            "/pets": {
                "servers": [{"url": "/v2"}],
                "get": {
                    "servers": [{"url": "/v3"}],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert [surface.url for surface in surfaces] == ["https://example.test/v3/pets"]
    assert surfaces[0].meta["server_base"] == "https://example.test/v3"


def test_server_variables_use_declared_defaults():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.2",
        "servers": [
            {
                "url": "/{version}",
                "variables": {
                    "version": {"default": "v7", "enum": ["v7", "v8"]}
                },
            }
        ],
        "paths": {
            "/status": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert [surface.url for surface in surfaces] == ["https://example.test/v7/status"]


def test_out_of_scope_operation_server_is_inventory_skipped():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.2",
        "paths": {
            "/internal": {
                "get": {
                    "servers": [{"url": "https://outside.invalid/api"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert surfaces == []
    assert engine.swagger_inventory["skipped_out_of_scope_server_operations"] == 1


def test_server_variable_without_default_fails_closed():
    spec_url = "https://example.test/openapi.json"
    spec = {
        "openapi": "3.1.2",
        "servers": [{"url": "/{version}", "variables": {"version": {}}}],
        "paths": {
            "/status": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    engine = APIEngine(config(), requester=Requester(spec_url, spec))

    surfaces = engine.load_swagger(spec_url)

    assert surfaces == []
    assert engine.errors
    assert "missing its required default" in engine.errors[0]["error"]
