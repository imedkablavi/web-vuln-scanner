import argparse
import json
import time
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


FORM_USERS = {
    "low_user": "lowpass",
    "peer_user": "peerpass",
    "admin_user": "adminpass",
}
API_USERS = {
    "api_user": "apipass",
}
STATIC_SESSIONS = {
    "LOW_USER_SESSION": "low_user",
    "PEER_USER_SESSION": "peer_user",
    "ADMIN_USER_SESSION": "admin_user",
}


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: N802
        return

    def _send(self, status: int, body: str, content_type: str = "text/plain", headers=None):
        if isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "MockServer/2.0")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload: dict, headers=None):
        self._send(status, json.dumps(payload), "application/json", headers=headers)

    def _now(self) -> float:
        return time.time()

    def _cookie_map(self) -> dict:
        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return {}
        return {key: morsel.value for key, morsel in cookie.items()}

    def _bearer_token(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return ""
        return header.split(" ", 1)[1].strip()

    def _session_entry(self):
        session_value = self._cookie_map().get("session", "")
        if not session_value:
            return None
        if session_value in STATIC_SESSIONS:
            return {"actor": STATIC_SESSIONS[session_value], "expires_at": self._now() + 3600, "dynamic": False}
        entry = self.server.session_store.get(session_value)
        if entry and entry["expires_at"] > self._now():
            return entry
        return None

    def _token_entry(self):
        token = self._bearer_token()
        if not token:
            return None
        entry = self.server.access_tokens.get(token)
        if entry and entry["expires_at"] > self._now():
            return entry
        return None

    def _actor(self):
        token_entry = self._token_entry()
        if token_entry:
            return token_entry["actor"]
        session_entry = self._session_entry()
        if session_entry:
            return session_entry["actor"]
        return "anonymous"

    def _auth_status(self):
        token = self._bearer_token()
        if token:
            entry = self.server.access_tokens.get(token)
            if entry is None:
                return {"type": "bearer", "status": "missing", "actor": "anonymous"}
            if entry["expires_at"] <= self._now():
                return {"type": "bearer", "status": "expired", "actor": entry["actor"]}
            return {"type": "bearer", "status": "valid", "actor": entry["actor"]}
        session_value = self._cookie_map().get("session", "")
        if session_value:
            if session_value in STATIC_SESSIONS:
                return {"type": "cookie", "status": "valid", "actor": STATIC_SESSIONS[session_value]}
            entry = self.server.session_store.get(session_value)
            if entry is None:
                return {"type": "cookie", "status": "missing", "actor": "anonymous"}
            if entry["expires_at"] <= self._now():
                return {"type": "cookie", "status": "expired", "actor": entry["actor"]}
            return {"type": "cookie", "status": "valid", "actor": entry["actor"]}
        return {"type": "none", "status": "missing", "actor": "anonymous"}

    def _expired_login_redirect(self):
        self._send(302, "redirect-login", headers={"Location": "/login?expired=1"})

    def _issue_session(self, actor: str, ttl_seconds: int = 3) -> str:
        value = f"sess-{actor}-{uuid.uuid4().hex[:10]}"
        self.server.session_store[value] = {"actor": actor, "expires_at": self._now() + ttl_seconds}
        return value

    def _issue_tokens(self, actor: str, ttl_seconds: int = 2):
        access_token = f"atk-{actor}-{uuid.uuid4().hex[:10]}"
        refresh_token = f"rtk-{actor}-{uuid.uuid4().hex[:10]}"
        self.server.access_tokens[access_token] = {"actor": actor, "expires_at": self._now() + ttl_seconds}
        self.server.refresh_tokens[refresh_token] = {"actor": actor, "expires_at": self._now() + 30}
        return access_token, refresh_token, ttl_seconds

    def _issue_document(self, actor: str, title: str, classification: str):
        doc_id = str(self.server.next_document_id)
        self.server.next_document_id += 1
        self.server.document_store[doc_id] = {
            "doc_id": doc_id,
            "owner": actor,
            "title": title,
            "classification": classification,
        }
        return self.server.document_store[doc_id]

    def _parse_body(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                return json.loads(raw_body), raw_body
            except ValueError:
                return {}, raw_body
        parsed = parse_qs(raw_body)
        return {key: values[0] if values else "" for key, values in parsed.items()}, raw_body

    def _require_cookie_auth(self):
        auth = self._auth_status()
        if auth["type"] == "cookie" and auth["status"] == "expired":
            self._expired_login_redirect()
            return None
        if auth["type"] != "cookie" or auth["status"] != "valid":
            self._send(401, "Unauthorized")
            return None
        return auth["actor"]

    def _require_bearer_auth(self):
        auth = self._auth_status()
        if auth["type"] == "bearer" and auth["status"] == "expired":
            self._send(401, "Token expired")
            return None
        if auth["type"] == "bearer" and auth["status"] == "valid":
            return auth["actor"]
        self._send(401, "Unauthorized")
        return None

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            html = """
            <html>
              <head><title>Mock App</title></head>
              <body>
                <h1>Mock App</h1>
                <img src="/logo.svg" alt="Mock logo" />
                <a href="/clean">Clean</a>
                <a href="/login">Login</a>
                <a href="/spa-login">SPA Login</a>
                <a href="/dashboard">Dashboard</a>
                <a href="/spa-dashboard">SPA Dashboard</a>
                <a href="/sqli?id=1">SQLi Link</a>
                <a href="/sqli_bool?id=1">Boolean SQLi Link</a>
                <a href="/idor?doc=1">IDOR Link</a>
                <a href="/idor_protected?doc=2">Protected IDOR Link</a>
                <a href="/auth_safe?doc=1">Auth Safe Link</a>
                <a href="/auth_bypass?doc=1">Auth Bypass Link</a>
                <a href="/auth_masked?doc=1">Auth Masked Link</a>
                <a href="/api/info?item=1">API Info</a>
                <a href="/api/profile">API Profile</a>
                <a href="/legacy-redirect">Legacy Redirect</a>
                <a href="/verbose-error">Verbose Error</a>
                <form action="/sqli" method="get">
                  <input type="text" name="id" value="1"/>
                  <button type="submit">Submit</button>
                </form>
              </body>
            </html>
            """
            self._send(200, html, "text/html", headers={"Set-Cookie": "sessionid=demo-session; Path=/"})
            return

        if parsed.path == "/logo.svg":
            svg = "<svg xmlns='http://www.w3.org/2000/svg' width='64' height='64'><rect width='64' height='64' fill='#1f4f99'/><text x='10' y='36' fill='white'>Mock</text></svg>"
            self._send(200, svg, "image/svg+xml")
            return

        if parsed.path == "/login":
            csrf_value = f"csrf-{uuid.uuid4().hex[:8]}"
            html = f"""
            <html>
              <head><title>Mock Login</title></head>
              <body>
                <h1>Login</h1>
                <form action="/login" method="post">
                  <input type="hidden" name="csrf" value="{csrf_value}" />
                  <input type="text" name="username" value="" />
                  <input type="password" name="password" value="" />
                  <button type="submit">Login</button>
                </form>
              </body>
            </html>
            """
            self._send(200, html, "text/html", headers={"Set-Cookie": f"csrf={csrf_value}; Path=/"})
            return

        if parsed.path == "/spa-login":
            spa_nonce = f"spa-{uuid.uuid4().hex[:8]}"
            html = f"""
            <html>
              <head><title>SPA Login</title></head>
              <body>
                <h1>SPA Login</h1>
                <button id="open-login" type="button">Open Login Form</button>
                <form id="spa-form" action="/spa-login" method="post" style="display:none">
                  <input type="hidden" name="browser_nonce" value="" />
                  <input type="text" name="username" value="" />
                  <input type="password" name="password" value="" />
                  <button id="spa-submit" type="submit">Sign In</button>
                </form>
                <script>
                  window.__spaNonce = "{spa_nonce}";
                  document.getElementById("open-login").addEventListener("click", function () {{
                    document.querySelector('input[name="browser_nonce"]').value = window.__spaNonce;
                    document.getElementById("spa-form").style.display = "block";
                  }});
                </script>
              </body>
            </html>
            """
            self._send(200, html, "text/html", headers={"Set-Cookie": f"spa_nonce={spa_nonce}; Path=/"})
            return

        if parsed.path == "/dashboard":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            html = f"<html><body><h1>Dashboard</h1><p>Actor: {actor}</p><a href=\"/logout\">Logout</a></body></html>"
            self._send(200, html, "text/html")
            return

        if parsed.path == "/spa-dashboard":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            html = f"<html><body><h1>SPA Dashboard</h1><p>Actor: {actor}</p><a href=\"/logout\">Logout</a></body></html>"
            self._send(200, html, "text/html")
            return

        if parsed.path == "/clean":
            self._send(200, "clean-ok")
            return

        if parsed.path == "/api/info":
            item = params.get("item", ["1"])[0]
            payload = json.dumps({"item": item, "status": "ok", "owner": "public"})
            self._send(
                200,
                payload,
                "application/json",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            return

        if parsed.path == "/api/profile":
            actor = self._require_bearer_auth()
            if actor is None:
                return
            self._json(200, {"actor": actor, "scope": "api", "status": "authenticated"})
            return

        if parsed.path == "/openapi.json":
            spec = {
                "swagger": "2.0",
                "host": f"{self.server.server_address[0]}:{self.server.server_address[1]}",
                "schemes": ["http"],
                "paths": {
                    "/api/info": {
                        "get": {
                            "summary": "Public item info",
                            "parameters": [{"name": "item", "in": "query", "type": "string"}],
                            "responses": {"200": {"description": "ok"}},
                        }
                    },
                    "/api/profile": {
                        "get": {
                            "summary": "Authenticated API profile",
                            "responses": {"200": {"description": "ok"}, "401": {"description": "unauthorized"}},
                        }
                    },
                },
            }
            self._send(200, json.dumps(spec), "application/json")
            return

        if parsed.path == "/legacy-redirect":
            self._send(302, "redirect", headers={"Location": "http://legacy.example.invalid/login"})
            return

        if parsed.path == "/verbose-error":
            body = "Traceback (most recent call last):\n  File 'app.py', line 10, in handler\nRuntimeError: demo failure"
            self._send(500, body)
            return

        if parsed.path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main")
            return

        if parsed.path == "/.env.bak":
            self._send(200, "APP_ENV=dev\nDB_PASSWORD=demo-pass\nAPI_KEY=mock-debug-key")
            return

        if parsed.path == "/debug/config.json":
            payload = json.dumps({"debug": True, "password": "demo-pass", "api_key": "mock-debug-key"})
            self._send(200, payload, "application/json")
            return

        if parsed.path == "/backup.zip":
            self._send(200, b"PK\x03\x04demo-backup", "application/zip")
            return

        if parsed.path == "/sqli":
            id_val = params.get("id", [""])[0]
            if "'" in id_val:
                self._send(500, "SQLSTATE[42000]: syntax error near ' input")
            else:
                self._send(200, f"Item {id_val} safe")
            return

        if parsed.path == "/sqli_bool":
            id_val = params.get("id", [""])[0]
            if "' AND '1'='2" in id_val:
                self._send(200, "No rows matched this filter")
            elif "' OR '1'='1" in id_val:
                self._send(200, "All rows returned because the predicate evaluated true")
            elif "'" in id_val:
                self._send(500, "SQLSTATE[42000]: syntax error near ' input")
            else:
                self._send(200, f"Single row for id={id_val}")
            return

        if parsed.path == "/idor":
            doc = params.get("doc", ["1"])[0]
            if not doc.isdigit():
                self._send(400, "Invalid document")
                return
            if doc == "1":
                body = "Document 1 for user A"
            elif doc == "2":
                body = "Document 2 for user B - exposed to anyone"
            else:
                body = f"Document {doc} is unavailable"
            self._send(200, body)
            return

        if parsed.path == "/idor_protected":
            doc = params.get("doc", ["1"])[0]
            if doc == "1":
                self._send(200, "Document 1 for user A (protected)")
            else:
                self._send(403, "Forbidden")
            return

        if parsed.path == "/auth_safe":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            doc = params.get("doc", ["1"])[0]
            owners = {"1": "low_user", "2": "peer_user"}
            owner = owners.get(doc, "low_user")
            if actor not in {owner, "admin_user"}:
                self._send(403, "Forbidden")
                return
            payload = {"doc": doc, "owner": owner, "classification": "internal", "title": f"Safe Document {doc}"}
            self._json(200, payload)
            return

        if parsed.path == "/auth_bypass":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            doc = params.get("doc", ["1"])[0]
            payload = {
                "doc": doc,
                "owner": "low_user",
                "classification": "restricted",
                "title": "Payroll Report",
                "email": "owner@example.test",
            }
            self._json(200, payload)
            return

        if parsed.path == "/auth_masked":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            doc = params.get("doc", ["1"])[0]
            if actor == "peer_user":
                payload = {
                    "doc": doc,
                    "owner": "redacted",
                    "classification": "restricted",
                    "title": "Payroll Report",
                    "email": "masked@example.test",
                }
            else:
                payload = {
                    "doc": doc,
                    "owner": "low_user",
                    "classification": "restricted",
                    "title": "Payroll Report",
                    "email": "owner@example.test",
                }
            self._json(200, payload)
            return

        if parsed.path == "/workflow/documents/view":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            doc_id = params.get("doc", [""])[0]
            document = self.server.document_store.get(doc_id)
            if document is None:
                self._send(404, "Document not found")
                return
            if actor not in {document["owner"], "admin_user"}:
                self._send(403, "Forbidden")
                return
            self._json(200, document)
            return

        if parsed.path == "/workflow/documents/view_bypass":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            doc_id = params.get("doc", [""])[0]
            document = self.server.document_store.get(doc_id)
            if document is None:
                self._send(404, "Document not found")
                return
            self._json(200, document)
            return

        self._send(404, "not-found")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        payload, raw_body = self._parse_body()

        if parsed.path == "/login":
            cookies = self._cookie_map()
            csrf_cookie = cookies.get("csrf", "")
            csrf_form = payload.get("csrf", "")
            username = payload.get("username", "")
            password = payload.get("password", "")
            if not csrf_cookie or csrf_cookie != csrf_form:
                self._send(403, "CSRF validation failed")
                return
            if FORM_USERS.get(username) != password:
                html = "<html><body><h1>Login</h1><p>Invalid credentials</p></body></html>"
                self._send(200, html, "text/html")
                return
            session_value = self._issue_session(username, ttl_seconds=2)
            self._send(302, "logged-in", headers={"Location": "/dashboard", "Set-Cookie": f"session={session_value}; Path=/; Max-Age=2"})
            return

        if parsed.path == "/spa-login":
            cookies = self._cookie_map()
            username = payload.get("username", "")
            password = payload.get("password", "")
            browser_nonce = payload.get("browser_nonce", "")
            if not browser_nonce or browser_nonce != cookies.get("spa_nonce", ""):
                self._send(403, "Browser nonce validation failed")
                return
            if FORM_USERS.get(username) != password:
                html = "<html><body><h1>SPA Login</h1><p>Invalid credentials</p></body></html>"
                self._send(200, html, "text/html")
                return
            session_value = self._issue_session(username, ttl_seconds=5)
            html = """
            <html>
              <body>
                <div id="login-success">Login complete</div>
                <script>
                  localStorage.setItem("access_token", "browser-session");
                  window.location = "/spa-dashboard";
                </script>
              </body>
            </html>
            """
            self._send(200, html, "text/html", headers={"Set-Cookie": f"session={session_value}; Path=/; Max-Age=2"})
            return

        if parsed.path == "/api/login":
            username = payload.get("username", "")
            password = payload.get("password", "")
            if API_USERS.get(username) != password:
                self._json(401, {"error": "invalid_credentials"})
                return
            access_token, refresh_token, expires_in = self._issue_tokens(username, ttl_seconds=1)
            self._json(200, {"access_token": access_token, "refresh_token": refresh_token, "expires_in": expires_in})
            return

        if parsed.path == "/api/refresh":
            refresh_token = payload.get("refresh_token", "")
            entry = self.server.refresh_tokens.get(refresh_token)
            if entry is None or entry["expires_at"] <= self._now():
                self._json(401, {"error": "refresh_failed"})
                return
            access_token, next_refresh_token, expires_in = self._issue_tokens(entry["actor"], ttl_seconds=2)
            self._json(200, {"access_token": access_token, "refresh_token": next_refresh_token, "expires_in": expires_in})
            return

        if parsed.path == "/workflow/documents":
            actor = self._require_cookie_auth()
            if actor is None:
                return
            title = payload.get("title", "Untitled Document")
            classification = payload.get("classification", "internal")
            document = self._issue_document(actor, title, classification)
            self._json(201, document)
            return

        if parsed.path == "/graphql":
            if "__schema" in raw_body:
                payload = {
                    "data": {
                        "__schema": {
                            "types": [
                                {"name": "Query", "fields": [{"name": "item"}]},
                                {"name": "Item", "fields": [{"name": "id"}, {"name": "status"}]},
                            ]
                        }
                    }
                }
                self._send(200, json.dumps(payload), "application/json")
                return
            self._send(200, json.dumps({"data": {"item": {"id": "1", "status": "ok"}}}), "application/json")
            return

        self._send(404, "not-found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0, help="Port to bind the mock server")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), MockHandler)
    server.session_store = {}
    server.access_tokens = {}
    server.refresh_tokens = {}
    server.document_store = {}
    server.next_document_id = 100
    host, port = server.server_address
    print(f"[mock_server] listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
