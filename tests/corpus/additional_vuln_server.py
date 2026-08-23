from __future__ import annotations

import ipaddress
import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen


SSTI_PAYLOAD = "scanner{{1337*17}}canary"
SSTI_RENDERED = "scanner22729canary"
CRLF_MARKER = "crlf-safe-marker"


class AdditionalVulnHandler(BaseHTTPRequestHandler):
    """Local-only deterministic fixtures for additional detector QA."""

    def log_message(self, format, *args):  # noqa: N802
        return

    def _send(self, status: int, body: str, headers=None, content_type: str = "text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict, headers=None):
        self._send(status, json.dumps(payload), headers=headers, content_type="application/json")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

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

        if parsed.path == "/ssrf":
            target = params.get("url", [""])[0]
            candidate = urlparse(target)
            try:
                host_is_loopback = candidate.hostname == "localhost" or ipaddress.ip_address(candidate.hostname or "").is_loopback
            except ValueError:
                host_is_loopback = False
            if candidate.scheme != "http" or not host_is_loopback:
                self._send(403, "callback-blocked")
                return
            try:
                with urlopen(target, timeout=0.75) as response:  # noqa: S310 - fixture is loopback-only by construction
                    fetched = response.read(256).decode("utf-8", errors="ignore")
            except Exception:
                self._send(502, "callback-failed")
                return
            self._send(200, f"fetched:{fetched}")
            return

        if parsed.path == "/ssrf-safe":
            self._send(403, "server-side fetching disabled")
            return

        if parsed.path == "/host-header":
            host = self.headers.get("Host", "fixture.invalid")
            self._send(200, f"reset_url=https://{host}/reset?token=fixture")
            return

        if parsed.path == "/host-header-safe":
            self._send(200, "reset_url=https://canonical.example.test/reset?token=fixture")
            return

        if parsed.path == "/cors-vuln":
            origin = self.headers.get("Origin", "")
            headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            } if origin else {}
            self._send(200, "cors-private-data", headers=headers)
            return

        if parsed.path == "/cors-safe":
            origin = self.headers.get("Origin", "")
            headers = {}
            if origin == "https://trusted.example.test":
                headers = {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                    "Vary": "Origin",
                }
            self._send(200, "cors-private-data", headers=headers)
            return

        if parsed.path == "/dom-xss":
            html = """<!doctype html><html><body><div id='sink'></div><script>
            const value = decodeURIComponent(window.location.hash.slice(1));
            document.getElementById('sink').innerHTML = value;
            </script></body></html>"""
            self._send(200, html, content_type="text/html; charset=utf-8")
            return

        if parsed.path == "/dom-xss-safe":
            html = """<!doctype html><html><body><div id='sink'></div><script>
            const value = decodeURIComponent(window.location.hash.slice(1));
            document.getElementById('sink').textContent = value;
            </script></body></html>"""
            self._send(200, html, content_type="text/html; charset=utf-8")
            return

        self._send(404, "not-found")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        payload = self._read_json()
        query = str(payload.get("query", ""))

        if parsed.path == "/graphql-vuln":
            if "__schema" in query:
                self._json(200, {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "Query"}]}}})
                return
            if "scannerDefinitelyMissingField" in query:
                self._json(
                    200,
                    {
                        "data": None,
                        "errors": [
                            {
                                "message": "Cannot query field scannerDefinitelyMissingField",
                                "extensions": {
                                    "exception": {
                                        "type": "RuntimeError",
                                        "stacktrace": [
                                            "Traceback (most recent call last):",
                                            "  File /srv/app/graphql.py:42 in resolve",
                                        ],
                                    }
                                },
                            }
                        ],
                    },
                )
                return
            self._json(200, {"data": {"__typename": "Query"}})
            return

        if parsed.path == "/graphql-safe":
            if "__schema" in query:
                self._json(200, {"data": None, "errors": [{"message": "Introspection is disabled"}]})
                return
            if "scannerDefinitelyMissingField" in query:
                self._json(200, {"data": None, "errors": [{"message": "Cannot query requested field"}]})
                return
            self._json(200, {"data": {"__typename": "Query"}})
            return

        self._send(404, "not-found")
