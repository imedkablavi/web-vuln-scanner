from __future__ import annotations

import threading
from http.server import HTTPServer

import pytest

from core.request_manager import RequestManager
from layers.directory_query_verification import DirectoryQueryVerifier
from layers.jwt_server_validation import JWTServerValidationVerifier
from layers.oauth_code_flow_verification import OAuthCodeFlowVerifier
from tests.corpus.advanced_vuln_server import AdvancedVulnHandler, JWT_CONTROL, JWT_NEGATIVE


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


@pytest.mark.parametrize(
    ("mode", "vulnerable_path", "safe_path", "finding_type"),
    [
        ("ldap", "/ldap-vuln", "/ldap-safe", "LDAP Injection"),
        ("xpath", "/xpath-vuln", "/xpath-safe", "XPath Injection"),
    ],
)
def test_directory_query_positive_and_negative(advanced_corpus, mode, vulnerable_path, safe_path, finding_type):
    common = {
        "explicit_opt_in": True,
        "mode": mode,
        "field": "query",
        "success_json_path": "matched",
        "expected_value": True,
    }
    vuln_cfg = cfg_for("directory_query", {**common, "endpoint_url": advanced_corpus + vulnerable_path})
    safe_cfg = cfg_for("directory_query", {**common, "endpoint_url": advanced_corpus + safe_path})

    vuln, _ = DirectoryQueryVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = DirectoryQueryVerifier(RequestManager(safe_cfg), safe_cfg).scan()

    assert any(f.type == finding_type and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_jwt_server_rejection_positive_and_negative(advanced_corpus, monkeypatch):
    control_env = "SCANNER_JWT_CONTROL"
    negative_env = "SCANNER_JWT_NEGATIVE"
    monkeypatch.setenv(control_env, JWT_CONTROL)
    monkeypatch.setenv(negative_env, JWT_NEGATIVE)
    common = {
        "explicit_opt_in": True,
        "control_token_env": control_env,
        "negative_token_env": negative_env,
        "negative_token_class": "synthetic-invalid-signature",
        "success_marker": "jwt-protected-ok",
    }
    vuln_cfg = cfg_for("jwt_server", {**common, "endpoint_url": f"{advanced_corpus}/jwt-server-vuln"})
    safe_cfg = cfg_for("jwt_server", {**common, "endpoint_url": f"{advanced_corpus}/jwt-server-safe"})

    vuln, meta = JWTServerValidationVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = JWTServerValidationVerifier(RequestManager(safe_cfg), safe_cfg).scan()

    assert meta["raw_tokens_persisted"] is False
    assert any(f.type == "JWT Invalid Token Accepted" and f.verification_status == "verified" for f in vuln)
    assert all(f.evidence.get("raw_tokens_recorded") is False for f in vuln)
    assert safe == []


def test_oauth_code_flow_pkce_nonce_and_reuse_positive_and_negative(advanced_corpus):
    common = {
        "explicit_opt_in": True,
        "client_id": "scanner-local-client",
        "redirect_uri": f"{advanced_corpus}/oauth-code-callback",
        "expect_id_token": True,
    }
    vuln_cfg = cfg_for(
        "oauth_code_flow",
        {
            **common,
            "authorization_url": f"{advanced_corpus}/oauth-code-vuln/authorize",
            "token_url": f"{advanced_corpus}/oauth-code-vuln/token",
        },
    )
    safe_cfg = cfg_for(
        "oauth_code_flow",
        {
            **common,
            "authorization_url": f"{advanced_corpus}/oauth-code-safe/authorize",
            "token_url": f"{advanced_corpus}/oauth-code-safe/token",
        },
    )

    vuln, meta = OAuthCodeFlowVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = OAuthCodeFlowVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    types = {f.type for f in vuln}

    assert meta["max_requests"] == 5
    assert {"OAuth PKCE Verification Weakness", "OIDC Nonce Binding Weakness", "OAuth Authorization Code Reuse"} <= types
    assert safe == []


def test_next_wave_verifiers_fail_closed_by_default():
    config = make_config()
    requester = RequestManager(config)
    assert DirectoryQueryVerifier(requester, config).scan()[0] == []
    assert JWTServerValidationVerifier(requester, config).scan()[0] == []
    assert OAuthCodeFlowVerifier(requester, config).scan()[0] == []


def test_directory_query_external_target_requires_second_opt_in():
    config = cfg_for(
        "directory_query",
        {
            "explicit_opt_in": True,
            "mode": "ldap",
            "endpoint_url": "https://example.test/search",
            "field": "query",
            "allow_external_probes": False,
        },
    )
    findings, meta = DirectoryQueryVerifier(None, config).scan()
    assert findings == []
    assert meta["skipped"]
