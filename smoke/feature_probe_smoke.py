from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from core.models import AttackSurface
from core.request_manager import RequestManager
from layers.active_web_probes import ActiveWebProbeScanner
from layers.browser_xss import BrowserXSSVerifier
from layers.xml_checks import XMLParserProbeScanner


ROOT_BODY = (
    "<html><body><h1>Feature Probe Fixture</h1>"
    "<p>This is a stable same-origin reference document used only by the scanner smoke test. "
    "Its body is intentionally long enough for response similarity comparison and contains no secrets.</p>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return

    def _send(self, status, body, content_type="text/html"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self._send(200, ROOT_BODY)
            return
        if parsed.path == "/fetch":
            target = params.get("url", [""])[0]
            expected = f"http://127.0.0.1:{self.server.server_address[1]}/"
            if target == expected:
                self._send(200, ROOT_BODY)
            else:
                self._send(200, "<html><body>fetch endpoint baseline</body></html>")
            return
        if parsed.path == "/reflect":
            value = params.get("q", [""])[0]
            self._send(200, f"<html><body><div id='result'>{value}</div></body></html>")
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/xml":
            self._send(404, "not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        match = re.search(r'<!ENTITY\s+wvs_probe\s+"([^"]+)">', body)
        if not match:
            self._send(400, "invalid xml", "text/plain")
            return
        token = match.group(1)
        self._send(200, f"<wvs><probe>{token}</probe></wvs>", "application/xml")


@dataclass
class APIEngineFixture:
    surface: AttackSurface

    def get_endpoints(self):
        return [self.surface]


def config(port: int):
    return {
        "scope": {
            "allowlist": ["127.0.0.1"],
            "include_domains": ["127.0.0.1"],
            "exclude_paths": [],
            "allow_private": True,
            "resolve_dns": False,
        },
        "concurrency": {
            "threads": 1,
            "per_host_concurrency": 1,
            "delay": 0,
            "timeout": 3,
            "max_retries": 0,
            "global_timeout_seconds": 30,
        },
        "request": {
            "timeouts": {"connect": 3, "read": 3},
            "max_retries": 0,
            "max_redirects": 2,
            "follow_redirects": False,
        },
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
        "active_checks": {
            "web": {
                "enabled": True,
                "max_urls": 2,
                "max_params_per_url": 2,
                "max_requests": 12,
                "ssti": False,
                "crlf": False,
                "trace": False,
                "ssrf_same_origin": True,
            },
            "xml": {"enabled": True, "max_requests": 1},
        },
        "browser": {
            "xss_verification": {
                "enabled": True,
                "max_tests": 1,
                "timeout_ms": 5000,
            }
        },
        "target": f"http://127.0.0.1:{port}",
    }


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    origin = f"http://{host}:{port}"
    cfg = config(port)
    requester = RequestManager(cfg)

    try:
        baseline_response = requester.send(
            "GET",
            f"{origin}/fetch?url=baseline",
            allow_redirects=False,
        )
        active = ActiveWebProbeScanner(requester, cfg)
        active_findings, active_meta = active.scan(
            [
                {
                    "url": f"{origin}/fetch?url=baseline",
                    "text": baseline_response.text,
                }
            ]
        )
        if not any(
            finding.type == "Server-Side URL Fetch Behavior"
            for finding in active_findings
        ):
            raise SystemExit(
                f"same-origin URL fetch smoke failed: {active_meta}"
            )

        reflect_response = requester.send(
            "GET",
            f"{origin}/reflect?q=hello",
            allow_redirects=False,
        )
        browser = BrowserXSSVerifier(cfg)
        browser_findings, browser_meta = browser.verify(
            [
                {
                    "url": f"{origin}/reflect?q=hello",
                    "content_type": reflect_response.headers.get("Content-Type", ""),
                    "text": reflect_response.text,
                }
            ]
        )
        if not any(
            finding.type == "Reflected Cross-Site Scripting"
            and finding.verification_status == "verified"
            for finding in browser_findings
        ):
            raise SystemExit(f"browser XSS smoke failed: {browser_meta}")

        xml_surface = AttackSurface(
            url=f"{origin}/xml",
            method="POST",
            source="smoke",
            meta={
                "request_content_types": ["application/xml"],
                "content_type": "application/xml",
            },
        )
        xml_probe = XMLParserProbeScanner(requester, cfg)
        xml_findings, xml_meta = xml_probe.scan(APIEngineFixture(xml_surface))
        if not any(
            finding.type == "XML DTD Entity Processing"
            for finding in xml_findings
        ):
            raise SystemExit(f"XML parser smoke failed: {xml_meta}")

        print(
            "Feature probe smoke successful: same-origin URL fetch, browser XSS, internal XML entity."
        )
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
