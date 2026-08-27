from __future__ import annotations

import base64
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.request_manager import RequestManager
from layers.cache_poisoning_verification import CachePoisoningVerifier
from layers.csrf_verification import CSRFVerifier
from layers.file_upload_verification import FileUploadVerifier
from layers.jwt_validation import JWTValidationVerifier
from layers.nosql_verification import NoSQLVerifier
from layers.oauth_flow_verification import OAuthFlowVerifier
from layers.oidc_verification import OIDCVerifier
from layers.xxe_verification import XXEVerifier
from tests.corpus.additional_vuln_server import AdditionalVulnHandler


CALLBACK_MARKER = "extended-detector-callback-marker"


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
def extended_corpus():
    AdditionalVulnHandler._cache.clear()
    server = HTTPServer(("127.0.0.1", 0), AdditionalVulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        AdditionalVulnHandler._cache.clear()


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: N802
        return

    def do_GET(self):  # noqa: N802
        data = CALLBACK_MARKER.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def callback_url():
    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/proof"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _jwt(header, claims, signature="sig"):
    def enc(value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{enc(header)}.{enc(claims)}.{signature}"


def test_xxe_controlled_callback_positive_and_negative(extended_corpus, callback_url):
    vuln_cfg = cfg_for(
        "xxe",
        {
            "endpoint_url": f"{extended_corpus}/xxe-vuln",
            "callback_url": callback_url,
            "expected_marker": CALLBACK_MARKER,
        },
    )
    safe_cfg = cfg_for(
        "xxe",
        {
            "endpoint_url": f"{extended_corpus}/xxe-safe",
            "callback_url": callback_url,
            "expected_marker": CALLBACK_MARKER,
        },
    )
    vuln, _ = XXEVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = XXEVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.plugin == "xxe_verification" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_csrf_cross_site_without_token_positive_and_negative(extended_corpus):
    common = {
        "explicit_opt_in": True,
        "token_field": "csrf_token",
        "token_value": "local-csrf-token",
        "form_data": {"action": "preview"},
        "success_marker": "csrf-action-ok",
    }
    vuln_cfg = cfg_for("csrf", {**common, "endpoint_url": f"{extended_corpus}/csrf-vuln"})
    safe_cfg = cfg_for("csrf", {**common, "endpoint_url": f"{extended_corpus}/csrf-safe"})
    vuln_cfg["auth"]["cookies"] = {"session": "local-user"}
    safe_cfg["auth"]["cookies"] = {"session": "local-user"}

    vuln, _ = CSRFVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = CSRFVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.plugin == "csrf_verification" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_nosql_eq_operator_semantics_positive_and_negative(extended_corpus):
    common = {
        "explicit_opt_in": True,
        "field": "lookup",
        "control_value": "scanner-nosql-canary",
        "success_json_path": "matched",
        "expected_value": True,
    }
    vuln_cfg = cfg_for("nosql", {**common, "endpoint_url": f"{extended_corpus}/nosql-vuln"})
    safe_cfg = cfg_for("nosql", {**common, "endpoint_url": f"{extended_corpus}/nosql-safe"})
    vuln, _ = NoSQLVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = NoSQLVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.plugin == "nosql_verification" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_jwt_offline_policy_positive_and_negative(monkeypatch):
    env_name = "SCANNER_EXTENDED_TEST_JWT"
    insecure = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "local-user"}, "")
    monkeypatch.setenv(env_name, insecure)
    config = cfg_for(
        "jwt",
        {
            "token_env": env_name,
            "expected_issuer": "https://issuer.example.test",
            "expected_audience": "scanner-client",
            "require_exp": True,
            "allowed_algorithms": ["HS256"],
        },
    )
    findings, meta = JWTValidationVerifier(config).scan()
    assert meta["network_requests"] == 0
    assert any(f.type == "JWT Unsecured Algorithm" for f in findings)
    assert any(f.type == "JWT Missing Expiration" for f in findings)
    assert all(f.evidence.get("raw_token_recorded") is False for f in findings)

    safe = _jwt(
        {"alg": "HS256", "typ": "JWT"},
        {
            "sub": "local-user",
            "iss": "https://issuer.example.test",
            "aud": "scanner-client",
            "exp": int(time.time()) + 3600,
        },
        "synthetic-signature",
    )
    monkeypatch.setenv(env_name, safe)
    safe_findings, _ = JWTValidationVerifier(config).scan()
    assert safe_findings == []


def test_oidc_pkce_metadata_positive_and_negative(extended_corpus):
    vuln_cfg = cfg_for(
        "oidc",
        {
            "metadata_url": f"{extended_corpus}/oidc-vuln/.well-known/openid-configuration",
            "public_client": True,
        },
    )
    safe_cfg = cfg_for(
        "oidc",
        {
            "metadata_url": f"{extended_corpus}/oidc-safe/.well-known/openid-configuration",
            "public_client": True,
        },
    )
    vuln, _ = OIDCVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = OIDCVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.type == "OIDC PKCE S256 Not Advertised" for f in vuln)
    assert safe == []


def test_oauth_redirect_uri_validation_positive_and_negative(extended_corpus):
    redirect_uri = f"{extended_corpus}/oauth-callback"
    common = {
        "explicit_opt_in": True,
        "client_id": "scanner-local-client",
        "redirect_uri": redirect_uri,
        "allow_external_flow": False,
    }
    vuln_cfg = cfg_for(
        "oauth_flow",
        {**common, "authorization_url": f"{extended_corpus}/oauth-vuln/authorize"},
    )
    safe_cfg = cfg_for(
        "oauth_flow",
        {**common, "authorization_url": f"{extended_corpus}/oauth-safe/authorize"},
    )
    vuln, _ = OAuthFlowVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = OAuthFlowVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.type == "OAuth Redirect URI Validation Weakness" for f in vuln)
    assert safe == []


def test_file_upload_inline_html_positive_and_safe_download_negative(extended_corpus):
    vuln_cfg = cfg_for(
        "file_upload",
        {
            "explicit_opt_in": True,
            "upload_url": f"{extended_corpus}/upload-vuln",
            "response_url_json_path": "url",
        },
    )
    safe_cfg = cfg_for(
        "file_upload",
        {
            "explicit_opt_in": True,
            "upload_url": f"{extended_corpus}/upload-safe",
            "response_url_json_path": "url",
        },
    )
    vuln, _ = FileUploadVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = FileUploadVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.plugin == "file_upload_verification" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_cache_poisoning_unique_canary_positive_and_negative(extended_corpus):
    vuln_cfg = cfg_for(
        "cache_poisoning",
        {
            "explicit_opt_in": True,
            "url": f"{extended_corpus}/cache-vuln",
            "canary_host": "scanner-cache-canary.invalid",
        },
    )
    safe_cfg = cfg_for(
        "cache_poisoning",
        {
            "explicit_opt_in": True,
            "url": f"{extended_corpus}/cache-safe",
            "canary_host": "scanner-cache-canary.invalid",
        },
    )
    vuln, _ = CachePoisoningVerifier(RequestManager(vuln_cfg), vuln_cfg).scan()
    safe, _ = CachePoisoningVerifier(RequestManager(safe_cfg), safe_cfg).scan()
    assert any(f.plugin == "cache_poisoning_verification" and f.verification_status == "verified" for f in vuln)
    assert safe == []


def test_high_impact_verifiers_fail_closed_by_default():
    config = make_config()
    requester = RequestManager(config)
    assert XXEVerifier(requester, config).scan()[0] == []
    assert CSRFVerifier(requester, config).scan()[0] == []
    assert NoSQLVerifier(requester, config).scan()[0] == []
    assert JWTValidationVerifier(config).scan()[0] == []
    assert OIDCVerifier(requester, config).scan()[0] == []
    assert OAuthFlowVerifier(requester, config).scan()[0] == []
    assert FileUploadVerifier(requester, config).scan()[0] == []
    assert CachePoisoningVerifier(requester, config).scan()[0] == []


def test_extended_safety_boundaries():
    local_xxe_cfg = cfg_for(
        "xxe",
        {"callback_url": "http://127.0.0.1:8123/proof", "expected_marker": "x"},
    )
    assert XXEVerifier(None, local_xxe_cfg)._callback_allowed() is True
    file_xxe_cfg = cfg_for(
        "xxe",
        {"callback_url": "file:///etc/passwd", "expected_marker": "x"},
    )
    assert XXEVerifier(None, file_xxe_cfg)._callback_allowed() is False

    oauth_cfg = cfg_for(
        "oauth_flow",
        {
            "explicit_opt_in": True,
            "authorization_url": "http://127.0.0.1:8123/authorize",
            "client_id": "scanner-local-client",
            "redirect_uri": "http://127.0.0.1:8123/callback",
        },
    )
    oauth = OAuthFlowVerifier(None, oauth_cfg)
    assert oauth._flow_allowed(oauth.authorization_url, oauth.redirect_uri) is True
    assert oauth._flow_allowed("https://accounts.example.test/auth", "https://app.example.test/callback") is False

    bad_cache_cfg = cfg_for(
        "cache_poisoning",
        {
            "explicit_opt_in": True,
            "url": "http://127.0.0.1:8123/cache",
            "canary_host": "not-reserved.example.com",
        },
    )
    findings, meta = CachePoisoningVerifier(None, bad_cache_cfg).scan()
    assert findings == []
    assert meta["skipped"]
