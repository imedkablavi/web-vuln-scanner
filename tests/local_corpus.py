from __future__ import annotations

import html
import json
import re
import threading
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class RegressionCorpusServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.rate_limit_hits = 0


class RegressionCorpusHandler(BaseHTTPRequestHandler):
    server_version = "WebVulnRegressionCorpus/1.1"

    def log_message(self, format, *args):  # pragma: no cover - keep CI quiet
        return

    def _cookies(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        return {key: morsel.value for key, morsel in cookie.items()}

    def _send(self, status=200, body="", headers=None, content_type="text/plain; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)

        if parsed.path == "/safe":
            self._send(200, "constant safe response")
            return

        if parsed.path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value or '"' in value:
                self._send(200, "SQL syntax error near quoted input")
            else:
                self._send(200, "record:1")
            return

        if parsed.path == "/sqli-baseline-error":
            self._send(200, "SQL syntax error shown by a static diagnostics banner")
            return

        if parsed.path == "/auth/profile":
            session = self._cookies().get("session", "")
            if session in {"user-token", "admin-token"}:
                role = "admin" if session == "admin-token" else "user"
                self._send(200, json.dumps({"authenticated": True, "role": role}), content_type="application/json")
            else:
                self._send(401, json.dumps({"authenticated": False}), content_type="application/json")
            return

        if parsed.path == "/auth/admin":
            if self._cookies().get("session") == "admin-token":
                self._send(200, "admin-only")
            else:
                self._send(403, "forbidden")
            return

        if parsed.path == "/rate-limit":
            self.server.rate_limit_hits += 1
            if self.server.rate_limit_hits <= 2:
                self._send(429, "retry", headers={"Retry-After": "0"})
            else:
                self._send(200, "ok")
            return

        # All active-check fixtures below are synthetic localhost behavior.
        if parsed.path == "/experimental/xss":
            value = query.get("q", [""])[0]
            self._send(
                200,
                f"<!doctype html><html><body><div id='sink'>{value}</div></body></html>",
                content_type="text/html; charset=utf-8",
            )
            return
        if parsed.path == "/experimental/xss-safe":
            value = html.escape(query.get("q", [""])[0], quote=True)
            self._send(
                200,
                f"<!doctype html><html><body><div id='sink'>{value}</div></body></html>",
                content_type="text/html; charset=utf-8",
            )
            return

        if parsed.path == "/experimental/lfi":
            value = query.get("file", [""])[0]
            if "../" in value or "..\\" in value:
                if "win.ini" in value.lower():
                    self._send(200, "[extensions]\nsynthetic=true\n")
                else:
                    self._send(200, "root:x:0:0:synthetic:/root:/bin/false\n")
            else:
                self._send(200, "public help document")
            return
        if parsed.path == "/experimental/lfi-safe":
            self._send(200, "public help document")
            return

        if parsed.path == "/experimental/cmd":
            value = query.get("cmd", [""])[0]
            marker = re.search(r"\bWVS_CMD_[0-9a-f]{10}\b", value)
            if marker and (";" in value or "&&" in value):
                self._send(200, f"command output: {marker.group(0)}")
            else:
                self._send(200, "diagnostic status: ok")
            return
        if parsed.path == "/experimental/cmd-safe":
            self._send(200, "diagnostic status: ok")
            return

        if parsed.path == "/experimental/redirect":
            self._send(302, "redirect", headers={"Location": query.get("next", ["/safe"])[0]})
            return
        if parsed.path == "/experimental/redirect-safe":
            self._send(302, "redirect", headers={"Location": "/safe"})
            return

        self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth/login":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if (username, password) == ("user", "user-pass"):
            self._send(200, "logged-in", headers={"Set-Cookie": "session=user-token; HttpOnly; SameSite=Lax"})
            return
        if (username, password) == ("admin", "admin-pass"):
            self._send(200, "logged-in", headers={"Set-Cookie": "session=admin-token; HttpOnly; SameSite=Lax"})
            return
        self._send(401, "invalid")


@contextmanager
def run_regression_corpus():
    server = RegressionCorpusServer(("127.0.0.1", 0), RegressionCorpusHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
