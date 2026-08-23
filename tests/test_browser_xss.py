from __future__ import annotations

from layers.browser_xss import BrowserXSSVerifier


class FakeBrowserXSSVerifier(BrowserXSSVerifier):
    def _run_sync(self, candidates):
        return [
            {
                "confirmed": True,
                "final_url": candidate["probe_url"],
            }
            for candidate in candidates
        ]


def config(*, enabled=True, max_tests=2):
    return {
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "allow_private": False,
            "resolve_dns": False,
        },
        "browser": {
            "xss_verification": {
                "enabled": enabled,
                "max_tests": max_tests,
                "timeout_ms": 2000,
            }
        },
    }


def html_snapshot(url):
    return {
        "url": url,
        "content_type": "text/html; charset=utf-8",
        "text": "<html><body>search</body></html>",
    }


def test_browser_xss_marks_real_execution_as_verified():
    verifier = FakeBrowserXSSVerifier(config())
    findings, meta = verifier.verify(
        [html_snapshot("https://example.test/search?q=hello")]
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Reflected Cross-Site Scripting"
    assert finding.verification_status == "verified"
    assert finding.confidence == "HIGH"
    assert finding.severity == "HIGH"
    assert finding.evidence["browser_execution"] is True
    assert meta["tests_run"] == 1


def test_browser_xss_probe_url_encodes_payload_as_query_data():
    verifier = FakeBrowserXSSVerifier(config())
    marker = verifier._marker("https://example.test/search?q=hello", "q")
    payload = (
        '<svg onload="document.documentElement.setAttribute('
        f"'data-wvs-xss','{marker}'"
        ')"></svg>'
    )
    url = verifier._build_url(
        "https://example.test/search?q=hello&lang=en",
        "q",
        payload,
    )

    assert "<svg" not in url
    assert "%3Csvg" in url
    assert "lang=en" in url
    assert "data-wvs-xss" in url


def test_browser_xss_respects_candidate_cap():
    verifier = FakeBrowserXSSVerifier(config(max_tests=2))
    findings, meta = verifier.verify(
        [
            html_snapshot("https://example.test/a?a=1&b=2"),
            html_snapshot("https://example.test/b?c=3"),
        ]
    )
    assert len(findings) == 2
    assert meta["tests_run"] == 2
    assert meta["max_tests"] == 2


def test_browser_xss_is_disabled_by_default():
    verifier = BrowserXSSVerifier(config(enabled=False))
    findings, meta = verifier.verify(
        [html_snapshot("https://example.test/search?q=hello")]
    )
    assert findings == []
    assert meta["enabled"] is False
    assert meta["tests_run"] == 0
