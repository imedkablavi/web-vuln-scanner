from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Tuple

from core.models import Finding


def _decode_segment(segment: str) -> Dict[str, Any] | None:
    try:
        padding = "=" * ((4 - len(segment) % 4) % 4)
        raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _decode_jwt(token: str) -> tuple[Dict[str, Any], Dict[str, Any]] | None:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    header = _decode_segment(parts[0])
    payload = _decode_segment(parts[1])
    if header is None or payload is None:
        return None
    return header, payload


class AuthTokenPostureScanner:
    """Inspect already-configured or already-issued JWTs without modifying them."""

    def __init__(self, config):
        self.config = config
        layer = config.get("passive_checks", {}).get("auth_tokens", {})
        self.enabled = bool(layer.get("enabled", True))
        self.max_lifetime_seconds = max(
            60, int(layer.get("max_lifetime_seconds", 86400))
        )
        self.skipped: List[str] = []
        self.errors: List[Dict[str, Any]] = []

    def scan(self, auth_session_manager) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append("JWT posture checks are disabled by configuration.")
            return [], self._meta(0, 0)
        if auth_session_manager is None:
            self.skipped.append("No auth session manager was available for JWT posture checks.")
            return [], self._meta(0, 0)

        findings: List[Finding] = []
        scanned_actors = 0
        jwt_tokens = 0
        for actor in auth_session_manager.context.enabled_actors():
            token = ""
            ready = False
            state = auth_session_manager.states.get(actor.actor_id)
            if state is not None:
                ready = bool(
                    getattr(state, "actor_ready", False)
                    and getattr(state, "session_status", "") == "authenticated"
                )
                material = getattr(state, "session_material", None)
                token = str(getattr(material, "access_token", "") or "")
            if not token:
                token = str(getattr(actor, "bearer_token", "") or "")
            if not token:
                continue
            scanned_actors += 1
            decoded = _decode_jwt(token)
            if decoded is None:
                continue
            jwt_tokens += 1
            finding = self._evaluate(actor.actor_id, decoded[0], decoded[1], ready)
            if finding:
                findings.append(finding)

        return findings, self._meta(scanned_actors, jwt_tokens)

    def _evaluate(
        self,
        actor_id: str,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        ready: bool,
    ) -> Finding | None:
        issues = []
        severity = "INFO"
        algorithm = str(header.get("alg") or "").strip()
        if algorithm.lower() == "none":
            issues.append("token declares alg=none")
            severity = "HIGH" if ready else "MEDIUM"

        exp = payload.get("exp")
        iat = payload.get("iat")
        if exp is None:
            issues.append("exp claim is missing")
            if severity in {"INFO", "LOW"}:
                severity = "MEDIUM"

        lifetime = None
        if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
            lifetime = int(exp - iat)
            if lifetime > self.max_lifetime_seconds:
                issues.append(
                    f"declared lifetime exceeds {self.max_lifetime_seconds} seconds"
                )
                if severity == "INFO":
                    severity = "LOW"

        now = int(time.time())
        expired = isinstance(exp, (int, float)) and int(exp) < now
        if expired:
            issues.append("token is expired at inspection time")
            if severity == "INFO":
                severity = "LOW"

        if not issues:
            return None

        status = "detected" if ready else "suspected"
        confidence = "HIGH" if ready else "MEDIUM"
        return Finding(
            plugin="auth_token_posture",
            type="JWT Security Posture",
            title="JWT Security Posture Needs Review",
            category="authentication",
            severity=severity,
            confidence=confidence,
            surface_id=f"jwt:{actor_id}",
            url="",
            evidence={
                "actor_id": actor_id,
                "actor_ready": ready,
                "algorithm": algorithm or "unspecified",
                "issues": issues,
                "claims_present": sorted(str(key) for key in payload.keys()),
                "issuer_present": "iss" in payload,
                "audience_present": "aud" in payload,
                "expiration_present": exp is not None,
                "issued_at_present": iat is not None,
                "declared_lifetime_seconds": lifetime,
            },
            remediation=(
                "Use a signed JWT algorithm appropriate for the trust model, validate the algorithm explicitly, "
                "set bounded expiration, and validate issuer/audience where those claims define the token's security boundary."
            ),
            reproduction={"source": "local_token_metadata_review", "actor_id": actor_id},
            verification_status=status,
            scanner_mode="auth-passive",
            reproducible=True,
            target={"source": "auth-session", "actor_id": actor_id},
            notes=[
                "The scanner decoded JWT metadata locally. It did not alter, re-sign, brute-force, or replay a modified token."
            ],
        )

    def _meta(self, scanned_actors: int, jwt_tokens: int) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "actors_with_tokens": scanned_actors,
            "jwt_tokens_inspected": jwt_tokens,
            "max_lifetime_seconds": self.max_lifetime_seconds,
            "errors": self.errors,
            "skipped": self.skipped,
        }
