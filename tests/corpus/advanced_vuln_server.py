from __future__ import annotations

import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse


LDAP_CANARY = "scanner-directory-canary*)(scannerAudit=1"
XPATH_CANARY = "scanner-directory-canary' or @scannerAudit='1"
JWT_CONTROL = "valid.synthetic.token"
JWT_NEGATIVE = "invalid.synthetic.token"


def _b64url(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _synthetic_id_token(nonce: str) -> str:
    return f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': 'local-user', 'nonce': nonce})}."


class AdvancedVulnHandler(BaseHTTPRequestHandler):
    """Local-only deterministic fixtures for the next verifier wave."""

    oauth_codes = {}
    oauth_counter = 0

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
        values = parse_qs(raw.decode("utf-8", errors="ignore"))
        return {key: items[0] if items else "" for key, items in values.items()}

    def _origin(self) -> str:
        return f"http://{self.headers.get('Host', '127.0.0.1')}"

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path in {"/jwt-server-vuln", "/jwt-server-safe"}:
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {JWT_CONTROL}":
                self._send(200, "jwt-protected-ok")
                return
            if parsed.path == "/jwt-server-vuln" and auth == f"Bearer {JWT_NEGATIVE}":
                self._send(200, "jwt-protected-ok")
                return
            self._send(401, "jwt-rejected")
            return

        if parsed.path in {"/oauth-code-vuln/authorize", "/oauth-code-safe/authorize"}:
            if params.get("client_id", [""])[0] != "scanner-local-client":
                self._json(400, {"error": "invalid_client"})
                return
            redirect_uri = params.get("redirect_uri", [""])[0]
            expected_redirect = f"{self._origin()}/oauth-code-callback"
            if redirect_uri != expected_redirect:
                self._json(400, {"error": "invalid_redirect_uri"})
                return

            self.__class__.oauth_counter += 1
            code = f"synthetic-code-{self.__class__.oauth_counter}"
            safe = parsed.path.startswith("/oauth-code-safe/")
            self.__class__.oauth_codes[code] = {
                "safe": safe,
                "challenge": params.get("code_challenge", [""])[0],
                "nonce": params.get("nonce", [""])[0],
                "consumed": False,
            }
            location = f"{redirect_uri}?{urlencode({'code': code, 'state': params.get('state', [''])[0]})}"
            self._send(302, "oauth-code-redirect", headers={"Location": location})
            return

        self._send(404, "not-found")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        raw = self._read_body()

        if parsed.path in {"/ldap-vuln", "/ldap-safe", "/xpath-vuln", "/xpath-safe"}:
            payload = self._json_from_body(raw)
            query = str(payload.get("query", "") or "")
            if parsed.path == "/ldap-vuln":
                self._json(200, {"matched": query == LDAP_CANARY})
                return
            if parsed.path == "/xpath-vuln":
                self._json(200, {"matched": query == XPATH_CANARY})
                return
            self._json(200, {"matched": False})
            return

        if parsed.path in {"/oauth-code-vuln/token", "/oauth-code-safe/token"}:
            form = self._form_from_body(raw)
            code = form.get("code", "")
            entry = self.__class__.oauth_codes.get(code)
            if not entry:
                self._json(400, {"error": "invalid_grant"})
                return

            verifier = form.get("code_verifier", "")
            calculated = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("ascii").rstrip("=")
            safe = parsed.path.startswith("/oauth-code-safe/")
            if safe:
                if entry.get("consumed"):
                    self._json(400, {"error": "invalid_grant"})
                    return
                if calculated != entry.get("challenge"):
                    self._json(400, {"error": "invalid_grant"})
                    return
                entry["consumed"] = True
                nonce = str(entry.get("nonce", "") or "")
            else:
                nonce = "wrong-synthetic-nonce"

            self._json(
                200,
                {
                    "access_token": "synthetic-access-token",
                    "token_type": "Bearer",
                    "id_token": _synthetic_id_token(nonce),
                },
            )
            return

        self._send(404, "not-found")
