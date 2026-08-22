from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from core.request_manager import RequestManager
from layers.active_web_probes import ActiveWebProbeScanner


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):  # noqa: N802
        return

    def _send(self, status: int, body: str, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        value = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
        headers = {}
        if "\r\nX-WVS-Canary: " in value:
            headers["X-WVS-Canary"] = value.split("\r\nX-WVS-Canary: ", 1)[1]
        body = value.replace("{{13*17}}", "221").replace("{{19*23}}", "437")
        self._send(200, body or "baseline", headers=headers)

    def do_TRACE(self):  # noqa: N802
        name = "X-WVS-Trace-Canary"
        value = self.headers.get(name, "")
        self._send(200, f"{name}: {value}")


@contextmanager
def probe_server():
    server = HTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def requester_config():
    return {
        "auth": {"cookies": {}, "headers": {}},
        "auth_verification": {"enabled": False},
        "scope": {
            "allowlist": [],
            "include_domains": ["127.0.0.1"],
            "exclude_paths": [],
            "allow_private": True,
            "resolve_dns": False,
        },
        "concurrency": {
            "threads": 1,
            "per_host_concurrency": 1,
            "delay": 0,
            "timeout": 2,
            "max_retries": 0,
        },
        "request": {
            "timeouts": {"connect": 2, "read": 2},
            "max_retries": 0,
            "max_redirects": 0,
            "follow_redirects": False,
        },
        "active_checks": {
            "web": {
                "enabled": True,
                "max_urls": 1,
                "ssti": True,
                "crlf": True,
                "trace": True,
            }
        },
    }


def test_active_probes_work_through_real_request_manager():
    with probe_server() as origin:
        requester = RequestManager(requester_config())
        scanner = ActiveWebProbeScanner(requester, requester_config())
        findings, meta = scanner.scan(
            [
                {
                    "url": f"{origin}/probe?q=base",
                    "text": "baseline",
                }
            ]
        )

    types = {finding.type for finding in findings}
    assert "Server-Side Template Injection" in types
    assert "HTTP Response Header Injection" in types
    assert "HTTP TRACE Enabled" in types
    assert meta["errors"] == []
    assert meta["requests_sent"] >= 4
