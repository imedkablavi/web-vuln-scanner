from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from core.models import Finding


class JWTServerValidationVerifier:
    """Server-side JWT rejection verifier using operator-supplied token samples.

    The scanner never forges, mutates, brute-forces, or persists tokens. The
    operator supplies one known-good control token and one intentionally invalid
    negative token via environment variables. A finding requires the endpoint to
    reject an unauthenticated request while accepting both token samples.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("jwt_server", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.control_token_env = str(layer.get("control_token_env", "") or "")
        self.negative_token_env = str(layer.get("negative_token_env", "") or "")
        self.negative_token_class = str(layer.get("negative_token_class", "operator-supplied-invalid") or "")
        self.success_marker = str(layer.get("success_marker", "") or "")
        self.success_statuses = {int(v) for v in (layer.get("success_statuses", [200]) or [200])}
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("JWT server validation disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("JWT server validation requires explicit_opt_in=true.")
        if not self.endpoint_url or not self.control_token_env or not self.negative_token_env:
            return [], self._meta("JWT server validation requires endpoint_url and two token environment references.")

        control_token = os.environ.get(self.control_token_env, "")
        negative_token = os.environ.get(self.negative_token_env, "")
        if not control_token or not negative_token:
            return [], self._meta("Configured JWT token environment variables are not both set.")
        if control_token == negative_token:
            return [], self._meta("Control and negative JWT samples must be different.")

        try:
            control = self._request(control_token, "jwt-control")
            negative = self._request(negative_token, "jwt-negative")
            unauthenticated = self.requester.send(
                "GET",
                self.endpoint_url,
                headers={"Authorization": "", "X-Scanner-Probe": "jwt-unauthenticated"},
                cookies={},
                timeout=self.timeout,
                source="jwt_server_validation",
            )
        except Exception as exc:
            self.errors.append({"url": self.endpoint_url, "error": str(exc)})
            return [], self._meta()

        control_ok = self._success(control)
        negative_ok = self._success(negative)
        unauth_ok = self._success(unauthenticated)
        if not (control_ok and negative_ok and not unauth_ok):
            return [], self._meta()

        finding = Finding(
            plugin="jwt_server_validation",
            type="JWT Invalid Token Accepted",
            title="Protected Endpoint Accepts Operator-Supplied Invalid JWT",
            category="authentication",
            severity="CRITICAL",
            confidence="HIGH",
            surface_id=f"jwt-server:{self.endpoint_url}",
            url=self.endpoint_url,
            evidence={
                "control_token_accepted": True,
                "negative_token_accepted": True,
                "unauthenticated_request_rejected": True,
                "negative_token_class": self.negative_token_class,
                "raw_tokens_recorded": False,
            },
            remediation=(
                "Reject invalid JWTs server-side after signature verification and enforce algorithm, key, issuer, "
                "audience, expiry, not-before, and token-type policy before granting access."
            ),
            reproduction={
                "method": "GET",
                "request_count": 3,
                "token_sources": "environment-variables",
                "raw_tokens_recorded": False,
                "token_mutation_or_forgery": False,
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-jwt-protected-endpoint"},
        )
        return [finding], self._meta()

    def _request(self, token: str, label: str):
        return self.requester.send(
            "GET",
            self.endpoint_url,
            headers={"Authorization": f"Bearer {token}", "X-Scanner-Probe": label},
            cookies={},
            timeout=self.timeout,
            source="jwt_server_validation",
        )

    def _success(self, response) -> bool:
        if response.status_code not in self.success_statuses:
            return False
        if self.success_marker:
            return self.success_marker in (response.text or "")
        return True

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "endpoint_configured": bool(self.endpoint_url),
            "max_requests": 3,
            "raw_tokens_persisted": False,
            "token_mutation_or_forgery": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
