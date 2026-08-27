from __future__ import annotations

import ipaddress
import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import urlopen


SSTI_PAYLOAD = "scanner{{1337*17}}canary"
SSTI_RENDERED = "scanner22729canary"
CRLF_MARKER = "crlf-safe-marker"
NOSQL_MARKER = "scanner-nosql-canary"
UPLOAD_MARKER = "scanner-upload-canary"


class AdditionalVulnHandler(BaseHTTPRequestHandler):
    """Local-only deterministic fixtures for additional detector QA."""

    _cache = {}

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

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    @staticmethod
    def _json_from_body(raw: bytes) -> dict:
        try:
            value = json.loads(raw.decode("utf-8", errors="ignore"))
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    @staticmethod
    def _form_from_body(raw: bytes) -> dict:
        parsed = parse_qs(raw.decode("utf-8", errors="ignore"))
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def _origin(self) -> str:
        return f"http://{self.headers.get('Host', '127.0.0.1')}"

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

        if parsed.path in {
            "/oidc-vuln/.well-known/openid-configuration",
            "/oidc-safe/.well-known/openid-configuration",
        }:
            origin = self._origin()
            safe = parsed.path.startswith("/oidc-safe/")
            prefix = "/oidc-safe" if safe else "/oidc-vuln"
            self._json(
                200,
                {
                    "issuer": f"{origin}{prefix}",
                    "authorization_endpoint": f"{origin}{prefix}/authorize",
                    "token_endpoint": f"{origin}{prefix}/token",
                    "jwks_uri": f"{origin}{prefix}/jwks",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "code_challenge_methods_supported": ["S256"] if safe else ["plain"],
                },
            )
            return

        if parsed.path in {"/oauth-vuln/authorize", "/oauth-safe/authorize"}:
            redirect_uri = params.get("redirect_uri", [""])[0]
            state = params.get("state", [""])[0]
            client_id = params.get("client_id", [""])[0]
            if client_id != "scanner-local-client":
                self._json(400, {"error": "invalid_client"})
                return
            expected = f"{self._origin()}/oauth-callback"
            safe = parsed.path.startswith("/oauth-safe/")
            if safe and redirect_uri != expected:
                self._json(400, {"error": "invalid_redirect_uri"})
                return
            if not redirect_uri:
                self._json(400, {"error": "missing_redirect_uri"})
                return
            location = f"{redirect_uri}?{urlencode({'code': 'synthetic-local-code', 'state': state})}"
            self._send(302, "oauth-redirect", headers={"Location": location})
            return

        if parsed.path == "/uploads/scanner-audit.html":
            self._send(
                200,
                f"<!doctype html><p>{UPLOAD_MARKER}</p>",
                content_type="text/html; charset=utf-8",
            )
            return

        if parsed.path == "/downloads/scanner-audit.html":
            self._send(
                200,
                f"<!doctype html><p>{UPLOAD_MARKER}</p>",
                headers={"Content-Disposition": 'attachment; filename="scanner-audit.html"'},
                content_type="application/octet-stream",
            )
            return

        if parsed.path == "/cache-vuln":
            key = self.path
            forwarded = self.headers.get("X-Forwarded-Host", "")
            if forwarded:
                body = f"asset_url=https://{forwarded}/static/app.js"
                self.__class__._cache[key] = body
                self._send(200, body, headers={"X-Cache": "MISS"})
                return
            if key in self.__class__._cache:
                self._send(200, self.__class__._cache[key], headers={"X-Cache": "HIT"})
                return
            self._send(200, "asset_url=https://canonical.example.test/static/app.js", headers={"X-Cache": "MISS"})
            return

        if parsed.path == "/cache-safe":
            self._send(200, "asset_url=https://canonical.example.test/static/app.js", headers={"X-Cache": "MISS"})
            return

        self._send(404, "not-found")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        raw = self._read_body()

        if parsed.path in {"/graphql-vuln", "/graphql-safe"}:
            payload = self._json_from_body(raw)
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

            if "__schema" in query:
                self._json(200, {"data": None, "errors": [{"message": "Introspection is disabled"}]})
                return
            if "scannerDefinitelyMissingField" in query:
                self._json(200, {"data": None, "errors": [{"message": "Cannot query requested field"}]})
                return
            self._json(200, {"data": {"__typename": "Query"}})
            return

        if parsed.path in {"/xxe-vuln", "/xxe-safe"}:
            text = raw.decode("utf-8", errors="ignore")
            if parsed.path == "/xxe-safe":
                self._send(400, "doctype-disabled")
                return
            match = re.search(r'<!ENTITY\s+scanner_xxe\s+SYSTEM\s+"([^"]+)"', text)
            if not match:
                self._send(400, "entity-missing")
                return
            target = match.group(1).replace("&amp;", "&")
            candidate = urlparse(target)
            try:
                loopback = candidate.hostname == "localhost" or ipaddress.ip_address(candidate.hostname or "").is_loopback
            except ValueError:
                loopback = False
            if candidate.scheme != "http" or not loopback:
                self._send(403, "external-entity-blocked")
                return
            try:
                with urlopen(target, timeout=0.75) as response:  # noqa: S310 - loopback-only fixture
                    resolved = response.read(256).decode("utf-8", errors="ignore")
            except Exception:
                self._send(502, "entity-fetch-failed")
                return
            self._send(200, f"resolved:{resolved}")
            return

        if parsed.path in {"/csrf-vuln", "/csrf-safe"}:
            form = self._form_from_body(raw)
            cookie = self.headers.get("Cookie", "")
            if "session=local-user" not in cookie:
                self._send(401, "login-required")
                return
            if parsed.path == "/csrf-vuln":
                self._send(200, "csrf-action-ok")
                return
            if form.get("csrf_token") == "local-csrf-token":
                self._send(200, "csrf-action-ok")
                return
            self._send(403, "csrf-rejected")
            return

        if parsed.path in {"/nosql-vuln", "/nosql-safe"}:
            payload = self._json_from_body(raw)
            lookup = payload.get("lookup")
            if parsed.path == "/nosql-vuln":
                matched = lookup == NOSQL_MARKER or lookup == {"$eq": NOSQL_MARKER}
                self._json(200, {"matched": matched, "mode": "operator-aware"})
                return
            if isinstance(lookup, dict):
                self._json(400, {"matched": False, "error": "scalar-required"})
                return
            self._json(200, {"matched": lookup == NOSQL_MARKER, "mode": "scalar-only"})
            return

        if parsed.path in {"/upload-vuln", "/upload-safe"}:
            text = raw.decode("utf-8", errors="ignore")
            accepted = 'filename="scanner-audit.html"' in text and UPLOAD_MARKER in text
            if not accepted:
                self._json(400, {"error": "invalid-upload"})
                return
            if parsed.path == "/upload-vuln":
                self._json(201, {"url": "/uploads/scanner-audit.html"})
                return
            self._json(201, {"url": "/downloads/scanner-audit.html"})
            return

        self._send(404, "not-found")
