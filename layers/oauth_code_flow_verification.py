from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.models import Finding


class OAuthCodeFlowVerifier:
    """Bounded public-client OAuth/OIDC code-flow verifier.

    By default both authorization and token endpoints must be loopback URLs.
    The verifier uses no client secret and no user credentials. It checks PKCE
    verifier rejection, state preservation, OIDC nonce binding, and single-use
    authorization-code behavior with a hard request cap.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("oauth_code_flow", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.allow_external_flow = bool(layer.get("allow_external_flow", False))
        self.authorization_url = str(layer.get("authorization_url", "") or "")
        self.token_url = str(layer.get("token_url", "") or "")
        self.client_id = str(layer.get("client_id", "") or "")
        self.redirect_uri = str(layer.get("redirect_uri", "") or "")
        self.expect_id_token = bool(layer.get("expect_id_token", True))
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 3)), 8.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("OAuth code-flow verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("OAuth code-flow verification requires explicit_opt_in=true.")
        if not all([self.authorization_url, self.token_url, self.client_id, self.redirect_uri]):
            return [], self._meta("OAuth code-flow verification requires authorization_url, token_url, client_id, and redirect_uri.")
        if not self._flow_allowed():
            return [], self._meta("OAuth code-flow verification blocked by loopback-only safety policy.")

        findings: List[Finding] = []
        try:
            wrong = self._authorize("pkce-negative")
            if not wrong["code"]:
                return [], self._meta()
            wrong_token = self._token_exchange(wrong["code"], "scanner-intentionally-wrong-verifier", "pkce-negative")
            if self._token_success(wrong_token):
                findings.append(self._finding(
                    "OAuth PKCE Verification Weakness",
                    "Token endpoint accepts an authorization code with the wrong PKCE verifier",
                    "CRITICAL",
                    {
                        "wrong_verifier_accepted": True,
                        "code_recorded": False,
                        "token_recorded": False,
                    },
                    request_count=2,
                ))

            valid = self._authorize("valid")
            if not valid["code"]:
                return findings, self._meta()
            if valid["state"] != valid["expected_state"]:
                findings.append(self._finding(
                    "OAuth State Not Preserved",
                    "Authorization response does not preserve the supplied state value",
                    "HIGH",
                    {"state_preserved": False, "code_recorded": False},
                    request_count=1,
                ))

            valid_token = self._token_exchange(valid["code"], valid["verifier"], "valid")
            if self._token_success(valid_token):
                token_payload = self._json_body(valid_token)
                id_token = str(token_payload.get("id_token", "") or "")
                if self.expect_id_token and id_token:
                    nonce = self._jwt_claim(id_token, "nonce")
                    if nonce != valid["nonce"]:
                        findings.append(self._finding(
                            "OIDC Nonce Binding Weakness",
                            "Returned ID token does not bind to the authorization request nonce",
                            "HIGH",
                            {
                                "nonce_matches": False,
                                "id_token_recorded": False,
                                "raw_nonce_recorded": False,
                            },
                            request_count=2,
                        ))

                replay = self._token_exchange(valid["code"], valid["verifier"], "replay")
                if self._token_success(replay):
                    findings.append(self._finding(
                        "OAuth Authorization Code Reuse",
                        "Token endpoint accepts a previously consumed authorization code",
                        "CRITICAL",
                        {
                            "consumed_code_reaccepted": True,
                            "code_recorded": False,
                            "token_recorded": False,
                        },
                        request_count=3,
                    ))
        except Exception as exc:
            self.errors.append({"url": self.authorization_url, "error": str(exc)})

        return findings, self._meta()

    def _authorize(self, label: str) -> Dict[str, str]:
        state = "scanner-" + secrets.token_hex(8)
        nonce = "scanner-" + secrets.token_hex(8)
        verifier = "scanner-" + secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest()).decode("ascii").rstrip("=")
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
        }
        parsed = urlparse(self.authorization_url)
        url = urlunparse(parsed._replace(query=urlencode(params)))
        response = self.requester.send(
            "GET",
            url,
            headers={"X-Scanner-Probe": f"oauth-code-{label}"},
            cookies={},
            timeout=self.timeout,
            allow_redirects=False,
            source="oauth_code_flow_verification",
        )
        location = str(response.headers.get("Location", "") or "")
        if not location.startswith(self.redirect_uri):
            return {"code": "", "state": "", "expected_state": state, "nonce": nonce, "verifier": verifier}
        query = parse_qs(urlparse(location).query)
        return {
            "code": str((query.get("code") or [""])[0]),
            "state": str((query.get("state") or [""])[0]),
            "expected_state": state,
            "nonce": nonce,
            "verifier": verifier,
        }

    def _token_exchange(self, code: str, verifier: str, label: str):
        return self.requester.send(
            "POST",
            self.token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "code": code,
                "code_verifier": verifier,
            },
            headers={"X-Scanner-Probe": f"oauth-token-{label}"},
            cookies={},
            timeout=self.timeout,
            source="oauth_code_flow_verification",
        )

    @staticmethod
    def _json_body(response) -> Dict[str, Any]:
        try:
            value = response.json()
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def _token_success(self, response) -> bool:
        return response.status_code < 400 and bool(self._json_body(response).get("access_token"))

    @staticmethod
    def _jwt_claim(token: str, claim: str) -> str:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return ""
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
            return str(data.get(claim, "") or "") if isinstance(data, dict) else ""
        except Exception:
            return ""

    def _finding(self, finding_type: str, title: str, severity: str, evidence: Dict[str, Any], request_count: int) -> Finding:
        return Finding(
            plugin="oauth_code_flow_verification",
            type=finding_type,
            title=title,
            category="authentication",
            severity=severity,
            confidence="HIGH",
            surface_id=f"oauth-code-flow:{finding_type.lower().replace(' ', '-')}:{self.authorization_url}",
            url=self.authorization_url,
            evidence=evidence,
            remediation=(
                "Require PKCE S256 for public clients, bind authorization responses to state and OIDC nonce, "
                "and enforce single-use short-lived authorization codes at the token endpoint."
            ),
            reproduction={
                "request_count_for_proof": request_count,
                "credentials_submitted": False,
                "client_secret_submitted": False,
                "codes_or_tokens_recorded": False,
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-public-oauth-client"},
        )

    def _flow_allowed(self) -> bool:
        if self.allow_external_flow:
            return True
        return all(self._is_loopback_url(value) for value in (self.authorization_url, self.token_url, self.redirect_uri))

    @staticmethod
    def _is_loopback_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return False
            if parsed.hostname == "localhost":
                return True
            return ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            return False

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "allow_external_flow": self.allow_external_flow,
            "max_requests": 5,
            "credentials_submitted": False,
            "client_secret_submitted": False,
            "codes_or_tokens_persisted": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
