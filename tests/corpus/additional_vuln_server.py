from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse


SSTI_PAYLOAD = "scanner{{1337*17}}canary"
SSTI_RENDERED = "scanner22729canary"
CRLF_MARKER = "crlf-safe-marker"


class AdditionalVulnHandler(BaseHTTPRequestHandler):
    """Local-only deterministic fixtures for additional detector QA."""

    def log_message(self, format, *args):  # noqa: N802
        return

    def _send(self, status: int, body: str, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/ssti":
            value = params.get("template", [""])[0]
            body = SSTI_RENDERED if value == SSTI_PAYLOAD else f"literal:{value}"
            self._send(200, body)
            return

        if parsed.path == "/ssti-safe":
            value = params.get("template", [""])[0]
            self._send(200, f"literal:{value}")
            return

        if parsed.path == "/crlf":
            value = params.get("next", [""])[0]
            headers = {}
            if "\r\nX-Scanner-Canary: crlf-safe-marker" in value:
                headers["X-Scanner-Canary"] = CRLF_MARKER
            self._send(200, "redirect-preview", headers=headers)
            return

        if parsed.path == "/crlf-safe":
            self._send(200, "redirect-preview")
            return

        self._send(404, "not-found")
