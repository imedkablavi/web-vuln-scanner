"""Product orchestration extension for bounded security verification layers.

The previously hardened orchestration is preserved verbatim in
``core.main_v2_base``. This wrapper appends independently bounded verification
layers without weakening the existing scope, plugin, auth, reporting, or release
behavior.
"""

from __future__ import annotations

import sys

from core import main_v2_base as _base
from core.request_manager import RequestManager
from layers.cache_poisoning_verification import CachePoisoningVerifier
from layers.cors_verification import CORSVerifier
from layers.csrf_verification import CSRFVerifier
from layers.dom_xss import DOMXSSVerifier
from layers.file_upload_verification import FileUploadVerifier
from layers.graphql_verification import GraphQLVerifier
from layers.jwt_validation import JWTValidationVerifier
from layers.nosql_verification import NoSQLVerifier
from layers.oauth_flow_verification import OAuthFlowVerifier
from layers.oidc_verification import OIDCVerifier
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

    try:
        cors_meta = _merge_layer_result(
            findings,
            layers,
            skipped,
            "cors_verification",
            CORSVerifier(requester, scanner_cfg).scan(discovery_urls),
        )
        if cors_meta.get("errors"):
            _base._mark_partial(scan_meta, "Bounded CORS verification encountered errors.")
    except Exception as exc:
        _base._mark_partial(scan_meta, f"Bounded CORS verification failed: {exc}")

    gql_endpoint = graphql_url or scanner_cfg.get("api", {}).get("graphql_url", "")
    try:
        graphql_meta = _merge_layer_result(
            findings,
            layers,
            skipped,
            "graphql_verification",
            GraphQLVerifier(requester, scanner_cfg).scan(gql_endpoint),
        )
        if graphql_meta.get("errors"):
            _base._mark_partial(scan_meta, "Bounded GraphQL verification encountered errors.")
    except Exception as exc:
        _base._mark_partial(scan_meta, f"Bounded GraphQL verification failed: {exc}")

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

    if active_cfg.get("xxe", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "xxe_verification", XXEVerifier(requester, scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "XXE verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"XXE verification failed: {exc}")

    if active_cfg.get("csrf", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "csrf_verification", CSRFVerifier(requester, scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "CSRF workflow verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"CSRF workflow verification failed: {exc}")

    if active_cfg.get("nosql", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "nosql_verification", NoSQLVerifier(requester, scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "NoSQL verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"NoSQL verification failed: {exc}")

    if active_cfg.get("jwt", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "jwt_validation", JWTValidationVerifier(scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "JWT validation encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"JWT validation failed: {exc}")

    if active_cfg.get("oidc", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "oidc_verification", OIDCVerifier(requester, scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "OIDC discovery verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"OIDC discovery verification failed: {exc}")

    if active_cfg.get("oauth_flow", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings, layers, skipped, "oauth_flow_verification", OAuthFlowVerifier(requester, scanner_cfg).scan()
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "OAuth flow verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"OAuth flow verification failed: {exc}")

    if active_cfg.get("file_upload", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings,
                layers,
                skipped,
                "file_upload_verification",
                FileUploadVerifier(requester, scanner_cfg).scan(),
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "File-upload verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"File-upload verification failed: {exc}")

    if active_cfg.get("cache_poisoning", {}).get("enabled", False):
        try:
            meta = _merge_layer_result(
                findings,
                layers,
                skipped,
                "cache_poisoning_verification",
                CachePoisoningVerifier(requester, scanner_cfg).scan(),
            )
            if meta.get("errors"):
                _base._mark_partial(scan_meta, "Cache-poisoning verification encountered errors.")
        except Exception as exc:
            _base._mark_partial(scan_meta, f"Cache-poisoning verification failed: {exc}")

    return findings, scan_meta


# The Typer command defined by the preserved base module resolves this global at
# call time, so replacing it upgrades both `python main_v2.py` and the wheel CLI.
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
