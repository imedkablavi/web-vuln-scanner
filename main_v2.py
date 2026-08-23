"""Product orchestration extension for bounded security verification layers.

The previously hardened orchestration is preserved verbatim in
``core.main_v2_base``.  This wrapper appends independently bounded verification
layers without weakening the existing scope, plugin, auth, reporting, or release
behavior.
"""

from __future__ import annotations

import sys

from core import main_v2_base as _base
from core.request_manager import RequestManager
from layers.cors_verification import CORSVerifier
from layers.dom_xss import DOMXSSVerifier
from layers.graphql_verification import GraphQLVerifier


_original_run_scan_async = getattr(
    _base,
    "_detector_extension_original_run_scan_async",
    _base.run_scan_async,
)
_base._detector_extension_original_run_scan_async = _original_run_scan_async


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

    try:
        cors_findings, cors_meta = CORSVerifier(requester, scanner_cfg).scan(discovery_urls)
        findings.extend(cors_findings)
        cors_meta["findings"] = len(cors_findings)
        layers["cors_verification"] = cors_meta
        skipped.extend(item for item in cors_meta.get("skipped", []) if item not in skipped)
        if cors_meta.get("errors"):
            _base._mark_partial(scan_meta, "Bounded CORS verification encountered errors.")
    except Exception as exc:
        _base._mark_partial(scan_meta, f"Bounded CORS verification failed: {exc}")

    gql_endpoint = graphql_url or scanner_cfg.get("api", {}).get("graphql_url", "")
    try:
        graphql_findings, graphql_meta = GraphQLVerifier(requester, scanner_cfg).scan(gql_endpoint)
        findings.extend(graphql_findings)
        graphql_meta["findings"] = len(graphql_findings)
        layers["graphql_verification"] = graphql_meta
        skipped.extend(item for item in graphql_meta.get("skipped", []) if item not in skipped)
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
