from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, List, Tuple

from core.models import Finding


def _b64url_json(segment: str) -> Dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    value = json.loads(raw.decode("utf-8"))
    return value if isinstance(value, dict) else {}


class JWTValidationVerifier:
    """Offline JWT claims/header posture verifier.

    The token is read from an environment variable and is never persisted in
    evidence. This layer does not forge tokens or test server acceptance.
    """

    def __init__(self, config: Dict[str, Any]):
        layer = config.get("active_verification", {}).get("jwt", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.token_env = str(layer.get("token_env", "") or "")
        self.expected_issuer = str(layer.get("expected_issuer", "") or "")
        self.expected_audience = str(layer.get("expected_audience", "") or "")
        self.require_exp = bool(layer.get("require_exp", True))
        self.allowed_algorithms = [str(item) for item in (layer.get("allowed_algorithms", []) or []) if str(item)]
        self.clock_skew_seconds = max(0, min(int(layer.get("clock_skew_seconds", 30)), 300))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("JWT validation disabled.")
        if not self.token_env:
            return [], self._meta("JWT validation requires token_env; inline tokens are intentionally unsupported.")

        token = os.environ.get(self.token_env, "")
        if not token:
            return [], self._meta(f"JWT token environment variable {self.token_env!r} is not set.")

        parts = token.split(".")
        if len(parts) != 3:
            return [self._finding(
                "Malformed JWT Structure",
                "JWT does not contain three compact-serialization segments",
                "MEDIUM",
                {"segments": len(parts)},
            )], self._meta()

        try:
            header = _b64url_json(parts[0])
            claims = _b64url_json(parts[1])
        except Exception as exc:
            self.errors.append({"kind": "decode", "error": type(exc).__name__})
            return [self._finding(
                "Malformed JWT Encoding",
                "JWT header or payload is not valid base64url JSON",
                "MEDIUM",
                {"decode_failed": True},
            )], self._meta()

        issues: List[Finding] = []
        alg = str(header.get("alg", "") or "")
        if not alg or alg.lower() == "none":
            issues.append(self._finding(
                "JWT Unsecured Algorithm",
                "JWT declares an unsecured or missing signing algorithm",
                "HIGH",
                {"algorithm": alg or "<missing>"},
            ))
        if self.allowed_algorithms and alg not in self.allowed_algorithms:
            issues.append(self._finding(
                "JWT Algorithm Outside Configured Policy",
                "JWT algorithm is outside the configured allowlist",
                "MEDIUM",
                {"algorithm": alg, "allowed_algorithms": self.allowed_algorithms},
            ))

        now = int(time.time())
        exp = claims.get("exp")
        if self.require_exp and exp is None:
            issues.append(self._finding(
                "JWT Missing Expiration",
                "JWT does not contain an exp claim required by policy",
                "MEDIUM",
                {"exp_present": False},
            ))
        elif isinstance(exp, (int, float)) and int(exp) < now - self.clock_skew_seconds:
            issues.append(self._finding(
                "JWT Expired Sample",
                "JWT sample is expired under the configured clock-skew policy",
                "LOW",
                {"expired": True},
            ))

        if self.expected_issuer:
            actual_issuer = str(claims.get("iss", "") or "")
            if actual_issuer != self.expected_issuer:
                issues.append(self._finding(
                    "JWT Issuer Policy Mismatch",
                    "JWT issuer does not match the configured expected issuer",
                    "MEDIUM",
                    {"issuer_matches_policy": False, "issuer_present": bool(actual_issuer)},
                ))

        if self.expected_audience:
            aud = claims.get("aud")
            if isinstance(aud, list):
                audience_ok = self.expected_audience in [str(item) for item in aud]
            else:
                audience_ok = str(aud or "") == self.expected_audience
            if not audience_ok:
                issues.append(self._finding(
                    "JWT Audience Policy Mismatch",
                    "JWT audience does not include the configured expected audience",
                    "MEDIUM",
                    {"audience_matches_policy": False, "audience_present": aud is not None},
                ))

        return issues, self._meta()

    def _finding(self, finding_type: str, title: str, severity: str, evidence: Dict[str, Any]) -> Finding:
        return Finding(
            plugin="jwt_validation",
            type=finding_type,
            title=title,
            category="authentication",
            severity=severity,
            confidence="HIGH",
            surface_id=f"jwt-policy:{finding_type.lower().replace(' ', '-')}",
            url="",
            evidence={**evidence, "raw_token_recorded": False, "source": "environment-variable"},
            remediation=(
                "Use an explicit algorithm allowlist, validate signature and key selection, and enforce exp, iss, aud, "
                "and nbf according to the application's trust policy."
            ),
            reproduction={
                "mode": "offline-token-posture",
                "token_source": "environment-variable",
                "network_requests": 0,
            },
            verification_status="detected",
            scanner_mode="offline-token-posture",
            reproducible=True,
            target={"source": "configured-jwt-sample"},
        )

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "token_env_configured": bool(self.token_env),
            "network_requests": 0,
            "raw_token_persisted": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
