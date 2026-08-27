"""Product orchestration extension for bounded security verification layers.

The previously hardened orchestration is preserved verbatim in
``core.main_v2_base``. This wrapper appends independently bounded verification
layers without weakening existing scope, auth, reporting, or release behavior.
"""

from __future__ import annotations

import sys

from core import main_v2_base as _base
from core.request_manager import RequestManager
from layers.cache_poisoning_verification import CachePoisoningVerifier
from layers.cors_verification import CORSVerifier
from layers.csrf_verification import CSRFVerifier
from layers.directory_query_verification import DirectoryQueryVerifier
from layers.dom_xss import DOMXSSVerifier
from layers.file_upload_verification import FileUploadVerifier
from layers.graphql_authorization_verification import GraphQLAuthorizationVerifier
from layers.graphql_verification import GraphQLVerifier
from layers.jwt_server_validation import JWTServerValidationVerifier
from layers.jwt_validation import JWTValidationVerifier
from layers.nosql_verification import NoSQLVerifier
from layers.oauth_code_flow_verification import OAuthCodeFlowVerifier
from layers.oauth_flow_verification import OAuthFlowVerifier
from layers.oidc_verification import OIDCVerifier
from layers.web_cache_deception_verification import WebCacheDeceptionVerifier
from layers.websocket_auth_verification import WebSocketAuthVerifier
from layers.xxe_verification import XXEVerifier


_original_run_scan_async = getattr(
    _base,
    "_detector_extension_original_run_scan_async",
    _base.run_scan_async,
)
_base._detector_extension_original_run_scan_async = _original_run_scan_async


def _merge_layer_result(findings, layers, skipped, key, result):
    layer_findings, layer_meta = result
    findings.extend(layer_findings)
    layer_meta["findings"] = len(layer_findings)
    layers[key] = layer_meta
    skipped.extend(item for item in layer_meta.get("skipped", []) if item not in skipped)
    return layer_meta


def _run_bounded_layer(scan_meta, findings, layers, skipped, key, label, callback):
    try:
        meta = _merge_layer_result(findings, layers, skipped, key, callback())
        if meta.get("errors"):
            _base._mark_partial(scan_meta, f"{label} encountered errors.")
    except Exception as exc:
        _base._mark_partial(scan_meta, f"{label} failed: {exc}")


async def run_scan_async(target, config, swagger_url, graphql_url, output_dir=None):
    findings, scan_meta = await _original_run_scan_async(
        target,
        config,
        swagger_url,
        graphql_url,
        output_dir=output_dir,
    )

    scanner_cfg = config["scanner"] if "scanner" in config else config
    layers = scan_meta.setdefault("execution", {}).setdefault("layers", {})
    skipped = scan_meta.setdefault("skipped_checks", [])
    discovery_urls = list(scan_meta.get("execution", {}).get("discovered_urls", []) or [])
    if target not in discovery_urls:
        discovery_urls.insert(0, target)

    requester = RequestManager(scanner_cfg)
    active_cfg = scanner_cfg.get("active_verification", {})

    _run_bounded_layer(
        scan_meta,
        findings,
        layers,
        skipped,
        "cors_verification",
        "Bounded CORS verification",
        lambda: CORSVerifier(requester, scanner_cfg).scan(discovery_urls),
    )

    gql_endpoint = graphql_url or scanner_cfg.get("api", {}).get("graphql_url", "")
    _run_bounded_layer(
        scan_meta,
        findings,
        layers,
        skipped,
        "graphql_verification",
        "Bounded GraphQL verification",
        lambda: GraphQLVerifier(requester, scanner_cfg).scan(gql_endpoint),
    )

    try:
        dom_findings, dom_meta = await DOMXSSVerifier(scanner_cfg).scan(discovery_urls)
        findings.extend(dom_findings)
        dom_meta["findings"] = len(dom_findings)
        layers["dom_xss_verification"] = dom_meta
        skipped.extend(item for item in dom_meta.get("skipped", []) if item not in skipped)
        if dom_meta.get("errors"):
            _base._mark_partial(scan_meta, "DOM-XSS browser verification encountered errors.")
    except Exception as exc:
        _base._mark_partial(scan_meta, f"DOM-XSS browser verification failed: {exc}")

    layer_specs = [
        ("xxe", "xxe_verification", "XXE verification", lambda: XXEVerifier(requester, scanner_cfg).scan()),
        ("csrf", "csrf_verification", "CSRF workflow verification", lambda: CSRFVerifier(requester, scanner_cfg).scan()),
        ("nosql", "nosql_verification", "NoSQL verification", lambda: NoSQLVerifier(requester, scanner_cfg).scan()),
        ("jwt", "jwt_validation", "JWT validation", lambda: JWTValidationVerifier(scanner_cfg).scan()),
        ("oidc", "oidc_verification", "OIDC discovery verification", lambda: OIDCVerifier(requester, scanner_cfg).scan()),
        ("oauth_flow", "oauth_flow_verification", "OAuth redirect/state verification", lambda: OAuthFlowVerifier(requester, scanner_cfg).scan()),
        ("file_upload", "file_upload_verification", "File-upload verification", lambda: FileUploadVerifier(requester, scanner_cfg).scan()),
        ("cache_poisoning", "cache_poisoning_verification", "Cache-poisoning verification", lambda: CachePoisoningVerifier(requester, scanner_cfg).scan()),
        ("directory_query", "directory_query_verification", "LDAP/XPath query verification", lambda: DirectoryQueryVerifier(requester, scanner_cfg).scan()),
        ("jwt_server", "jwt_server_validation", "JWT server validation", lambda: JWTServerValidationVerifier(requester, scanner_cfg).scan()),
        ("oauth_code_flow", "oauth_code_flow_verification", "OAuth code-flow verification", lambda: OAuthCodeFlowVerifier(requester, scanner_cfg).scan()),
        ("websocket_auth", "websocket_auth_verification", "WebSocket authentication verification", lambda: WebSocketAuthVerifier(requester, scanner_cfg).scan()),
        ("graphql_authorization", "graphql_authorization_verification", "GraphQL authorization verification", lambda: GraphQLAuthorizationVerifier(requester, scanner_cfg).scan()),
        ("web_cache_deception", "web_cache_deception_verification", "Web cache deception verification", lambda: WebCacheDeceptionVerifier(requester, scanner_cfg).scan()),
    ]

    for config_key, report_key, label, callback in layer_specs:
        if active_cfg.get(config_key, {}).get("enabled", False):
            _run_bounded_layer(scan_meta, findings, layers, skipped, report_key, label, callback)

    # HTTP request-smuggling/desync work intentionally remains a local research
    # corpus only. No raw-protocol production-target dispatcher is exposed here.
    return findings, scan_meta


_base.run_scan_async = run_scan_async
app = _base.app
load_config = _base.load_config
validate_threads = _base.validate_threads
scan = _base.scan


def __getattr__(name):
    return getattr(_base, name)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "scan":
        sys.argv.pop(1)
    app()
