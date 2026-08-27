from __future__ import annotations

import ipaddress
import secrets
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.models import Finding


class OAuthFlowVerifier:
    """Bounded OAuth authorization redirect/state verification.

    By default this verifier is restricted to loopback authorization + redirect
    endpoints. External-provider flow probing requires both explicit_opt_in and
    allow_external_flow. Requests are sent without scanner auth cookies.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("oauth_flow", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.allow_external_flow = bool(layer.get("allow_external_flow", False))
        self.authorization_url = str(layer.get("authorization_url", "") or "")
        self.client_id = str(layer.get("client_id", "") or "")
        self.redirect_uri = str(layer.get("redirect_uri", "") or "")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 3)), 8.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, authorization_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        endpoint = authorization_url or self.authorization_url
        if not self.enabled:
            return [], self._meta("OAuth flow verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("OAuth flow verification requires explicit_opt_in=true.")
        if not endpoint or not self.client_id or not self.redirect_uri:
            return [], self._meta("OAuth flow verification requires authorization_url, client_id, and redirect_uri.")
        if not self._flow_allowed(endpoint, self.redirect_uri):
            return [], self._meta("OAuth flow blocked by loopback-only safety policy.")

        state = "scanner-" + secrets.token_hex(8)
        baseline_url = self._build_authorization_url(endpoint, self.redirect_uri, state)
        attacker_redirect = "https://scanner-oauth-redirect.invalid/callback"
        negative_url = self._build_authorization_url(endpoint, attacker_redirect, state)

        try:
            baseline = self.requester.send(
                "GET",
                baseline_url,
                headers={"X-Scanner-Probe": "oauth-valid-redirect"},
                cookies={},
                timeout=self.timeout,
                allow_redirects=False,
                source="oauth_flow_verification",
            )
            negative = self.requester.send(
                "GET",
                negative_url,
                headers={"X-Scanner-Probe": "oauth-invalid-redirect"},
                cookies={},
                timeout=self.timeout,
                allow_redirects=False,
                source="oauth_flow_verification",
            )
        except Exception as exc:
            self.errors.append({"url": endpoint, "error": str(exc)})
            return [], self._meta()

        findings: List[Finding] = []
        baseline_location = str(baseline.headers.get("Location", "") or "")
        negative_location = str(negative.headers.get("Location", "") or "")

        if baseline_location.startswith(self.redirect_uri):
            echoed_state = self._query_value(baseline_location, "state")
            if echoed_state != state:
                findings.append(self._finding(
                    endpoint,
                    "OAuth State Not Preserved",
                    "Authorization response does not preserve the supplied state value",
                    "HIGH",
                    {
                        "baseline_redirect_accepted": True,
                        "state_preserved": False,
                        "location_recorded": False,
                    },
                ))

        if negative_location.startswith(attacker_redirect):
            findings.append(self._finding(
                endpoint,
                "OAuth Redirect URI Validation Weakness",
                "Authorization endpoint redirects to an unregistered canary redirect URI",
                "CRITICAL",
                {
                    "invalid_redirect_accepted": True,
                    "attacker_domain_class": "reserved-invalid-domain",
                    "location_recorded": False,
                },
            ))

        return findings, self._meta()

    def _finding(self, endpoint: str, finding_type: str, title: str, severity: str, evidence: Dict[str, Any]) -> Finding:
        return Finding(
            plugin="oauth_flow_verification",
            type=finding_type,
            title=title,
            category="authentication",
            severity=severity,
            confidence="HIGH",
            surface_id=f"oauth-flow:{finding_type.lower().replace(' ', '-')}:{endpoint}",
            url=endpoint,
            evidence=evidence,
            remediation=(
                "Require exact pre-registered redirect URI matching, preserve and validate state across authorization flows, "
                "and use PKCE S256 for public clients. Never place authorization codes in unvalidated redirect destinations."
            ),
            reproduction={
                "method": "GET",
                "request_count": 2,
                "credentials_submitted": False,
                "scanner_auth_cookies_sent": False,
                "invalid_redirect_class": "reserved-invalid-domain",
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-oauth-test-client"},
        )

    def _build_authorization_url(self, endpoint: str, redirect_uri: str, state: str) -> str:
        parsed = urlparse(endpoint)
        query = list(parse_qs(parsed.query, keep_blank_values=True).items())
        flattened = [(key, values[-1] if isinstance(values, list) and values else values) for key, values in query]
        flattened.extend(
            [
                ("client_id", self.client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("state", state),
                ("code_challenge", "scanner-audit-pkce-challenge"),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
            ]
        )
        return urlunparse(parsed._replace(query=urlencode(flattened)))

    def _flow_allowed(self, authorization_url: str, redirect_uri: str) -> bool:
        if self.allow_external_flow:
            return True
        return self._is_loopback_url(authorization_url) and self._is_loopback_url(redirect_uri)

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

    @staticmethod
    def _query_value(url: str, key: str) -> str:
        values = parse_qs(urlparse(url).query).get(key, [])
        return str(values[0]) if values else ""

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "allow_external_flow": self.allow_external_flow,
            "authorization_url_configured": bool(self.authorization_url),
            "client_id_configured": bool(self.client_id),
            "redirect_uri_configured": bool(self.redirect_uri),
            "max_requests": 2,
            "credentials_submitted": False,
            "scanner_auth_cookies_sent": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
