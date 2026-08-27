from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.models import Finding


def _json_path(value: Any, path: str):
    current = value
    for part in [item for item in str(path).split(".") if item]:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class NoSQLVerifier:
    """Bounded Mongo-style operator-semantic verifier using only $eq.

    The verifier compares a scalar control request with an equivalent `$eq`
    object at an explicitly configured user-input field. It never uses `$where`,
    regex DoS patterns, JavaScript expressions, authentication bypass operators,
    or destructive mutations.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("nosql", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.field = str(layer.get("field", "") or "")
        self.control_value = str(layer.get("control_value", "scanner-nosql-canary"))
        self.success_json_path = str(layer.get("success_json_path", "matched") or "matched")
        self.expected_value = layer.get("expected_value", True)
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, endpoint_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        endpoint = endpoint_url or self.endpoint_url
        if not self.enabled:
            return [], self._meta("NoSQL verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("NoSQL verification requires explicit_opt_in=true.")
        if not endpoint or not self.field:
            return [], self._meta("NoSQL verification requires endpoint_url and an explicit user-input field.")

        control_payload = {self.field: self.control_value}
        operator_payload = {self.field: {"$eq": self.control_value}}
        try:
            control = self.requester.send(
                "POST",
                endpoint,
                json=control_payload,
                headers={"X-Scanner-Probe": "nosql-scalar-control"},
                timeout=self.timeout,
                source="nosql_verification",
            )
            operator = self.requester.send(
                "POST",
                endpoint,
                json=operator_payload,
                headers={"X-Scanner-Probe": "nosql-eq-operator"},
                timeout=self.timeout,
                source="nosql_verification",
            )
        except Exception as exc:
            self.errors.append({"url": endpoint, "error": str(exc)})
            return [], self._meta()

        control_value = self._response_value(control)
        operator_value = self._response_value(operator)
        control_ok = control.status_code < 400 and control_value == self.expected_value
        operator_ok = operator.status_code < 400 and operator_value == self.expected_value
        if not (control_ok and operator_ok):
            return [], self._meta()

        finding = Finding(
            plugin="nosql_verification",
            type="NoSQL Operator Injection Semantics",
            title="User Input Accepts Mongo-Style Query Operator Semantics",
            category="injection",
            severity="MEDIUM",
            confidence="HIGH",
            surface_id=f"nosql:{endpoint}:{self.field}",
            url=endpoint,
            evidence={
                "field": self.field,
                "control_status": control.status_code,
                "operator_status": operator.status_code,
                "control_semantic_match": True,
                "eq_operator_semantic_match": True,
                "operator_used": "$eq",
            },
            remediation=(
                "Enforce a scalar schema for user-controlled query fields and reject object/operator input. "
                "Construct database filters from typed application values rather than passing client objects to the database driver."
            ),
            reproduction={
                "method": "POST",
                "content_type": "application/json",
                "request_count": 2,
                "operator_class": "equality-only",
                "field": self.field,
            },
            verification_status="verified",
            scanner_mode="active-bounded",
            reproducible=True,
            target={"source": "explicit-nosql-input"},
        )
        return [finding], self._meta()

    def _response_value(self, response):
        try:
            payload = response.json()
        except Exception:
            return None
        return _json_path(payload, self.success_json_path)

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "endpoint_configured": bool(self.endpoint_url),
            "field_configured": bool(self.field),
            "operator": "$eq",
            "max_requests": 2,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
