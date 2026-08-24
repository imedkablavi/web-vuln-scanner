from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.models import Finding
from core.requester_variants import requester_with_ephemeral_auth


class WebSocketAuthVerifier:
    """Verify authentication at an HTTP WebSocket upgrade boundary.

    This layer performs only the opening handshake. It does not send WebSocket
    frames, subscribe to channels, brute-force paths, or keep long-lived sockets.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("websocket_auth", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("WebSocket authentication verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("WebSocket authentication verification requires explicit_opt_in=true.")
        if not self.endpoint_url:
            return [], self._meta("WebSocket authentication verification requires endpoint_url.")

        auth_cfg = dict(self.requester.config.get("auth", {}) or {})
        auth_headers = dict(auth_cfg.get("headers", {}) or {})
        auth_cookies = dict(auth_cfg.get("cookies", {}) or {})
        if not auth_headers and not auth_cookies:
            return [], self._meta("WebSocket authentication verification requires configured authorized auth material.")

        upgrade = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "c2Nhbm5lci13cy1jYW5hcnk=",
        }
        authenticated_requester = requester_with_ephemeral_auth(
            self.requester,
            headers=auth_headers,
            cookies=auth_cookies,
        )
        anonymous_requester = requester_with_ephemeral_auth(self.requester)
        try:
            baseline = authenticated_requester.send(
                "GET",
                self.endpoint_url,
                headers={**upgrade, "X-Scanner-Probe": "websocket-authenticated-handshake"},
                timeout=self.timeout,
                allow_redirects=False,
                source="websocket_auth_verification",
            )
            anonymous = anonymous_requester.send(
                "GET",
                self.endpoint_url,
                headers={**upgrade, "X-Scanner-Probe": "websocket-unauthenticated-handshake"},
                cookies={},
                timeout=self.timeout,
                allow_redirects=False,
                source="websocket_auth_verification",
            )
        except Exception as exc:
            self.errors.append({"url": self.endpoint_url, "error": str(exc)})
            return [], self._meta()

        if baseline.status_code != 101 or anonymous.status_code != 101:
            return [], self._meta()

        finding = Finding(
            plugin="websocket_auth_verification",
            type="WebSocket Handshake Authentication Bypass",
            title="WebSocket Upgrade Succeeds Without Configured Authentication",
            category="authentication",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"websocket-auth:{self.endpoint_url}",
            url=self.endpoint_url,
            evidence={
                "authenticated_handshake_status": 101,
                "unauthenticated_handshake_status": 101,
                "websocket_frames_sent": 0,
                "auth_values_recorded": False,
                "requesters_isolated": True,
            },
            remediation=(
                "Require authentication before accepting the WebSocket upgrade, bind the resulting connection to "
                "an authenticated principal, and enforce authorization again for subscriptions and messages."
            ),
            reproduction={
                "request_count": 2,
                "handshake_only": True,
                "websocket_frames_sent": 0,
                "auth_values_recorded": False,
                "requesters_isolated": True,
            },
            verification_status="verified",
            scanner_mode="handshake-bounded",
            reproducible=True,
            target={"source": "explicit-websocket-endpoint"},
        )
        return [finding], self._meta()

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "max_requests": 2,
            "handshake_only": True,
            "websocket_frames_sent": 0,
            "requesters_isolated": True,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
