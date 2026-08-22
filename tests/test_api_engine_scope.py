from core.api_engine import APIEngine


def config():
    return {
        "target": "https://example.com",
        "scope": {
            "include_domains": ["*.example.com"],
            "allow_private": False,
            "resolve_dns": False,
            "exclude_paths": [],
        },
        "crawler": {"max_url_length": 2048},
    }


def test_api_engine_uses_boundary_aware_scope_policy():
    engine = APIEngine(config())
    assert engine._in_scope("https://api.example.com/openapi.json")
    assert engine._in_scope("https://example.com/openapi.json")
    assert not engine._in_scope("https://badexample.com/openapi.json")
    assert not engine._in_scope("https://example.com.evil.test/openapi.json")


def test_api_engine_refuses_raw_network_fallback():
    engine = APIEngine(config(), requester=None)
    result = engine.load_swagger("https://example.com/openapi.json")
    assert result == []
    assert engine.errors
    assert "RequestManager" in engine.errors[0]["error"]
