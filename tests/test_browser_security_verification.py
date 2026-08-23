from __future__ import annotations

import asyncio
import os
import threading
from http.server import HTTPServer

import pytest

from layers.dom_xss import DOMXSSVerifier
from tests.corpus.additional_vuln_server import AdditionalVulnHandler


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_BROWSER_SECURITY_TESTS") != "1",
    reason="Chromium security regression runs only in the dedicated local-browser CI gate.",
)


@pytest.fixture()
def browser_corpus():
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


def make_browser_config(output_dir: str):
    return {
        "scope": {"include_domains": [], "exclude_paths": [], "allow_private": True},
        "crawler": {"max_url_length": 2048},
        "browser": {
            "headless": True,
            "slow_mo": 0,
            "capture_trace": False,
            "capture_screenshots": False,
            "max_pages": 3,
            "max_actions_per_page": 1,
            "dom_xss": {"enabled": True, "max_urls": 2, "timeout_ms": 3000},
        },
        "auth": {"headers": {}, "cookies": {}},
        "output": {"directory": output_dir},
    }


def test_dom_xss_browser_execution_positive_and_negative(browser_corpus, tmp_path):
    config = make_browser_config(str(tmp_path / "browser-artifacts"))

    vulnerable_findings, vulnerable_meta = asyncio.run(
        DOMXSSVerifier(config).scan([f"{browser_corpus}/dom-xss"])
    )
    safe_findings, safe_meta = asyncio.run(
        DOMXSSVerifier(config).scan([f"{browser_corpus}/dom-xss-safe"])
    )

    assert vulnerable_meta["errors"] == []
    assert safe_meta["errors"] == []
    assert any(
        finding.plugin == "dom_xss_verification"
        and finding.verification_status == "verified"
        and finding.evidence.get("canary_executed") is True
        for finding in vulnerable_findings
    )
    assert not any(finding.plugin == "dom_xss_verification" for finding in safe_findings)

    reproduction = vulnerable_findings[0].reproduction
    assert reproduction["payload_class"] == "inert-dom-execution-canary"
    assert vulnerable_findings[0].evidence["network_callback_used"] is False
    assert vulnerable_findings[0].evidence["storage_or_cookie_access_used"] is False
