from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding


class OIDCVerifier:
    """Bounded OIDC discovery/configuration verification.

    This layer performs one metadata GET only. It does not initiate authorization
    flows, submit credentials, exchange codes, or mutate provider state.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("oidc", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.metadata_url = str(layer.get("metadata_url", "") or "")
        self.expected_issuer = str(layer.get("expected_issuer", "") or "")
        self.public_client = bool(layer.get("public_client", True))
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []
        self.observations: Dict[str, Any] = {}

    def scan(self, metadata_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        url = metadata_url or self.metadata_url
        if not self.enabled:
            return [], self._meta("OIDC verification disabled.")
        if not url:
            return [], self._meta("OIDC verification requires an explicit metadata_url.")

        try:
            response = self.requester.send(
                "GET",
                url,
                headers={"Accept": "application/json", "X-Scanner-Probe": "oidc-metadata"},
                timeout=self.timeout,
                source="oidc_verification",
            )
        except Exception as exc:
            self.errors.append({"url": url, "error": str(exc)})
            return [], self._meta()

        try:
            metadata = response.json()
        except Exception as exc:
            self.errors.append({"url": url, "error": f"invalid_json:{type(exc).__name__}"})
            return [], self._meta()

        if not isinstance(metadata, dict):
            return [], self._meta()

        findings: List[Finding] = []
        issuer = str(metadata.get("issuer", "") or "")
        methods = [str(item) for item in (metadata.get("code_challenge_methods_supported") or [])]
        self.observations = {
            "status": response.status_code,
            "issuer_present": bool(issuer),
            "pkce_methods": methods[:10],
            "authorization_endpoint_present": bool(metadata.get("authorization_endpoint")),
            "token_endpoint_present": bool(metadata.get("token_endpoint")),
        }

        if self.expected_issuer and issuer != self.expected_issuer:
            findings.append(self._finding(
                url,
                "OIDC Issuer Mismatch",
                "OIDC discovery issuer does not match configured trust policy",
                "HIGH",
                {"issuer_matches_policy": False},
            ))

        for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = str(metadata.get(key, "") or "")
            if value and not self._https_or_loopback(value):
                findings.append(self._finding(
                    url,
                    "OIDC Insecure Endpoint Transport",
                    f"OIDC metadata advertises a non-HTTPS {key}",
                    "HIGH",
                    {"metadata_field": key, "https_or_loopback": False},
                ))

        if self.public_client:
            if methods and "S256" not in methods:
                findings.append(self._finding(
                    url,
                    "OIDC PKCE S256 Not Advertised",
                    "OIDC metadata advertises PKCE methods but omits S256",
                    "MEDIUM",
                    {"pkce_methods": methods[:10], "s256_advertised": False},
                ))
            elif not methods:
                findings.append(Finding(
                    plugin="oidc_verification",
                    type="OIDC PKCE Capability Not Advertised",
                    title="OIDC discovery metadata does not advertise PKCE methods",
                    category="authentication",
                    severity="LOW",
                    confidence="LOW",
                    surface_id=f"oidc-pkce-unadvertised:{url}",
                    url=url,
                    evidence={"pkce_methods_present": False},
                    remediation="For public clients, support PKCE with S256 and advertise code_challenge_methods_supported when appropriate.",
                    reproduction={"method": "GET", "request_count": 1, "source": "oidc-discovery"},
                    verification_status="suspected",
                    scanner_mode="active-bounded",
                    reproducible=True,
                    target={"source": "oidc-discovery"},
                ))

        return findings, self._meta()

    def _finding(self, url: str, finding_type: str, title: str, severity: str, evidence: Dict[str, Any]) -> Finding:
        return Finding(
            plugin="oidc_verification",
            type=finding_type,
            title=title,
            category="authentication",
            severity=severity,
            confidence="HIGH",
            surface_id=f"oidc:{finding_type.lower().replace(' ', '-')}:{url}",
            url=url,
            evidence=evidence,
            remediation=(
                "Use exact issuer matching, HTTPS endpoints, and PKCE S256 for public clients. "
                "Keep discovery metadata aligned with the provider's actual authorization policy."
            ),
            reproduction={"method": "GET", "request_count": 1, "source": "oidc-discovery"},
            verification_status="verified",
            scanner_mode="active-bounded",
            reproducible=True,
            target={"source": "oidc-discovery"},
        )

    @staticmethod
    def _https_or_loopback(value: str) -> bool:
        try:
            parsed = urlparse(value)
            if parsed.scheme == "https":
                return True
            if parsed.scheme != "http" or not parsed.hostname:
                return False
            if parsed.hostname == "localhost":
                return True
            return ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            return False

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "metadata_url_configured": bool(self.metadata_url),
            "max_requests": 1,
            "observations": self.observations,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
