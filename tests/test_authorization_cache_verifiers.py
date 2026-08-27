from __future__ import annotations

import json
import threading
from http.server import HTTPServer

import pytest

from core.request_manager import RequestManager
from layers.graphql_authorization_verification import GraphQLAuthorizationVerifier
from layers.web_cache_deception_verification import WebCacheDeceptionVerifier
from layers.websocket_auth_verification import WebSocketAuthVerifier
from tests.corpus.advanced_vuln_server import AdvancedVulnHandler, GRAPHQL_SECRET, WCD_MARKER


def make_config():
    return {
        "scope": {"include_domains": [], "allow_private": True},
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 1,
            "threads": 1,
            "per_host_concurrency": 1,
            "global_timeout_seconds": 5,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
        "active_verification": {},
    }


def cfg_for(name, values):
    config = make_config()
    config["active_verification"][name] = {"enabled": True, **values}
    return config


@pytest.fixture()
def advanced_corpus():
    AdvancedVulnHandler.oauth_codes.clear()
    AdvancedVulnHandler.oauth_counter = 0
    AdvancedVulnHandler.wcd_cache.clear()
    server = HTTPServer(("127.0.0.1", 0), AdvancedVulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        AdvancedVulnHandler.oauth_codes.clear()
        AdvancedVulnHandler.oauth_counter = 0
        AdvancedVulnHandler.wcd_cache.clear()


def test_websocket_handshake_auth_positive_and_negative(advanced_corpus):
    common = {"explicit_opt_in": True}
    vuln_cfg = cfg_for("websocket_auth", {**common, "endpoint_url": f"{advanced_corpus}/ws-vuln"})
    safe_cfg = cfg_for("websocket_auth", {**common, "endpoint_url": f"{advanced_corpus}/ws-safe"})
    vuln_cfg["auth"]["headers"] = {"Authorization": "Bearer ws-valid-token"}
    safe_cfg["auth"]["headers"] = {"Authorization": "Bearer ws-valid-token"}

    vuln, meta = WebSocketAuthVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = WebSocketAuthVerifier(RequestManager(safe_cfg), safe_cfg).scan()

    assert meta["websocket_frames_sent"] == 0
    assert any(f.type == "WebSocket Handshake Authentication Bypass" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_graphql_cross_actor_authorization_positive_and_negative(advanced_corpus, monkeypatch):
    owner_env = "SCANNER_GRAPHQL_OWNER_HEADERS"
    peer_env = "SCANNER_GRAPHQL_PEER_HEADERS"
    monkeypatch.setenv(owner_env, json.dumps({"X-Actor": "owner"}))
    monkeypatch.setenv(peer_env, json.dumps({"X-Actor": "peer"}))
    common = {
        "explicit_opt_in": True,
        "query": "query { account { secret } }",
        "protected_json_path": "data.account.secret",
        "expected_value": GRAPHQL_SECRET,
        "baseline_headers_env": owner_env,
        "comparison_headers_env": peer_env,
        "baseline_actor_id": "owner",
        "comparison_actor_id": "peer",
    }
    vuln_cfg = cfg_for(
        "graphql_authorization",
        {**common, "endpoint_url": f"{advanced_corpus}/graphql-auth-vuln"},
    )
    safe_cfg = cfg_for(
        "graphql_authorization",
        {**common, "endpoint_url": f"{advanced_corpus}/graphql-auth-safe"},
    )

    vuln, meta = GraphQLAuthorizationVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = GraphQLAuthorizationVerifier(RequestManager(safe_cfg), safe_cfg).scan()

    assert meta["actor_header_values_persisted"] is False
    assert any(f.type == "GraphQL Cross-Actor Authorization Bypass" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_web_cache_deception_positive_and_negative(advanced_corpus):
    common = {
        "explicit_opt_in": True,
        "private_marker": WCD_MARKER,
        "cache_hit_header": "X-Cache",
        "cache_hit_value": "HIT",
    }
    vuln_cfg = cfg_for(
        "web_cache_deception",
        {**common, "url": f"{advanced_corpus}/wcd-vuln/account.css"},
    )
    safe_cfg = cfg_for(
        "web_cache_deception",
        {**common, "url": f"{advanced_corpus}/wcd-safe/account.css"},
    )
    vuln_cfg["auth"]["cookies"] = {"session": "wcd-owner"}
    safe_cfg["auth"]["cookies"] = {"session": "wcd-owner"}

    vuln, meta = WebCacheDeceptionVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = WebCacheDeceptionVerifier(RequestManager(safe_cfg), safe_cfg).scan()

    assert meta["private_marker_persisted"] is False
    assert any(f.type == "Web Cache Deception" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_authorization_cache_verifiers_fail_closed_by_default():
    config = make_config()
    requester = RequestManager(config)
    assert WebSocketAuthVerifier(requester, config).scan()[0] == []
    assert GraphQLAuthorizationVerifier(requester, config).scan()[0] == []
    assert WebCacheDeceptionVerifier(requester, config).scan()[0] == []
