from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

from core.models import Finding
from core.requester_variants import requester_with_ephemeral_auth


class GraphQLAuthorizationVerifier:
    """Cross-actor GraphQL field/object authorization verifier.

    Actor headers are supplied through environment variables containing JSON
    objects. Values are used only for the two configured requests and are never
    persisted in evidence.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("graphql_authorization", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.query = str(layer.get("query", "") or "")
        self.variables = dict(layer.get("variables", {}) or {})
        self.protected_json_path = str(layer.get("protected_json_path", "") or "")
        self.expected_value = layer.get("expected_value")
        self.baseline_headers_env = str(layer.get("baseline_headers_env", "") or "")
        self.comparison_headers_env = str(layer.get("comparison_headers_env", "") or "")
        self.baseline_actor_id = str(layer.get("baseline_actor_id", "owner") or "owner")
        self.comparison_actor_id = str(layer.get("comparison_actor_id", "peer") or "peer")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("GraphQL authorization verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("GraphQL authorization verification requires explicit_opt_in=true.")
        if not self.endpoint_url or not self.query or not self.protected_json_path:
            return [], self._meta("GraphQL authorization verification requires endpoint_url, query, and protected_json_path.")

        baseline_headers = self._headers_from_env(self.baseline_headers_env)
        comparison_headers = self._headers_from_env(self.comparison_headers_env)
        if baseline_headers is None or comparison_headers is None:
            return [], self._meta("GraphQL actor header environment variables are missing or invalid JSON objects.")

        try:
            baseline = self._request(baseline_headers, "graphql-owner")
            comparison = self._request(comparison_headers, "graphql-peer")
        except Exception as exc:
            self.errors.append({"url": self.endpoint_url, "error": str(exc)})
            return [], self._meta()

        baseline_value = self._json_path(baseline, self.protected_json_path)
        comparison_value = self._json_path(comparison, self.protected_json_path)
        if baseline_value != self.expected_value or comparison_value != self.expected_value:
            return [], self._meta()

        finding = Finding(
            plugin="graphql_authorization_verification",
            type="GraphQL Cross-Actor Authorization Bypass",
            title="Comparison Actor Can Read Protected GraphQL Object or Field",
            category="access-control",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"graphql-auth:{self.endpoint_url}:{self.protected_json_path}",
            url=self.endpoint_url,
            evidence={
                "protected_path": self.protected_json_path,
                "baseline_actor_received_expected_value": True,
                "comparison_actor_received_expected_value": True,
                "auth": {
                    "baseline_actor_ready": True,
                    "comparison_actor_ready": True,
                    "header_values_recorded": False,
                    "requesters_isolated": True,
                },
            },
            remediation=(
                "Enforce authorization in GraphQL resolvers for every protected object and field using the authenticated "
                "principal and resource ownership/role policy. Do not rely on UI visibility or query shape."
            ),
            reproduction={
                "request_count": 2,
                "query_source": "explicit-config",
                "actor_headers_source": "environment-variables",
                "header_values_recorded": False,
                "actor_requesters_isolated": True,
            },
            verification_status="verified",
            scanner_mode="cross-actor-bounded",
            reproducible=True,
            target={"source": "explicit-graphql-authorization-case"},
            baseline_actor_id=self.baseline_actor_id,
            comparison_actor_id=self.comparison_actor_id,
            actor_comparison={
                "baseline": {"protected_value_visible": True},
                "comparison": {"protected_value_visible": True},
            },
            authorization_signal="cross-actor-readable",
            auth_state={
                "actors": {
                    self.baseline_actor_id: {"session_status": "authenticated", "actor_ready": True},
                    self.comparison_actor_id: {"session_status": "authenticated", "actor_ready": True},
                }
            },
            actor_ready=True,
        )
        return [finding], self._meta()

    def _request(self, actor_headers: Dict[str, str], label: str):
        actor_requester = requester_with_ephemeral_auth(self.requester, headers=actor_headers, cookies={})
        return actor_requester.send(
            "POST",
            self.endpoint_url,
            json={"query": self.query, "variables": self.variables},
            headers={"X-Scanner-Probe": label},
            cookies={},
            timeout=self.timeout,
            source="graphql_authorization_verification",
        )

    @staticmethod
    def _headers_from_env(name: str):
        if not name:
            return None
        raw = os.environ.get(name, "")
        if not raw:
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        return {str(k): str(v) for k, v in value.items()}

    @staticmethod
    def _json_path(response, path: str):
        try:
            value = response.json()
        except Exception:
            return None
        for part in [item for item in path.split(".") if item]:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "max_requests": 2,
            "actor_header_values_persisted": False,
            "actor_requesters_isolated": True,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
