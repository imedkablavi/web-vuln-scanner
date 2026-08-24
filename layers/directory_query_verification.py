from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding


class DirectoryQueryVerifier:
    """Bounded LDAP/XPath query-semantic verifier.

    This verifier is disabled by default and loopback-only unless a separate
    allow_external_probes flag is set. It sends one scalar control request and
    one inert query-syntax canary request. It never performs writes, credential
    guessing, enumeration loops, or unbounded query expansion.
    """

    PAYLOADS = {
        "ldap": "scanner-directory-canary*)(scannerAudit=1",
        "xpath": "scanner-directory-canary' or @scannerAudit='1",
    }

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("directory_query", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.allow_external_probes = bool(layer.get("allow_external_probes", False))
        self.mode = str(layer.get("mode", "") or "").strip().lower()
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.field = str(layer.get("field", "query") or "query")
        self.control_value = str(layer.get("control_value", "scanner-directory-canary") or "")
        self.success_json_path = str(layer.get("success_json_path", "matched") or "matched")
        self.expected_value = layer.get("expected_value", True)
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta("Directory-query verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("Directory-query verification requires explicit_opt_in=true.")
        if self.mode not in self.PAYLOADS:
            return [], self._meta("directory_query.mode must be 'ldap' or 'xpath'.")
        if not self.endpoint_url or not self.field:
            return [], self._meta("Directory-query verification requires endpoint_url and field.")
        if not self._target_allowed(self.endpoint_url):
            return [], self._meta("Directory-query verification blocked by loopback-only safety policy.")

        control_body = {self.field: self.control_value}
        probe_body = {self.field: self.PAYLOADS[self.mode]}
        try:
            control = self.requester.send(
                "POST",
                self.endpoint_url,
                json=control_body,
                timeout=self.timeout,
                source="directory_query_verification",
            )
            probe = self.requester.send(
                "POST",
                self.endpoint_url,
                json=probe_body,
                timeout=self.timeout,
                source="directory_query_verification",
            )
        except Exception as exc:
            self.errors.append({"url": self.endpoint_url, "error": str(exc)})
            return [], self._meta()

        control_value = self._json_path(control, self.success_json_path)
        probe_value = self._json_path(probe, self.success_json_path)
        if control_value == self.expected_value or probe_value != self.expected_value:
            return [], self._meta()

        finding_type = "LDAP Injection" if self.mode == "ldap" else "XPath Injection"
        cwe = "CWE-90" if self.mode == "ldap" else "CWE-643"
        finding = Finding(
            plugin="directory_query_verification",
            type=finding_type,
            title=f"{finding_type} Query Semantics Accepted",
            category="injection",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"directory-query:{self.mode}:{self.endpoint_url}",
            url=self.endpoint_url,
            evidence={
                "mode": self.mode,
                "control_matched": False,
                "probe_matched": True,
                "query_canary_class": "inert-synthetic-filter",
                "cwe": cwe,
            },
            remediation=(
                "Use parameterized/query-builder APIs and treat user input as literal data. "
                "For LDAP escape RFC 4515 filter values; for XPath use variable binding or a safe query API."
            ),
            reproduction={
                "method": "POST",
                "request_count": 2,
                "field": self.field,
                "payload_class": "bounded-query-semantic-canary",
                "writes_performed": False,
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-directory-query-endpoint"},
        )
        return [finding], self._meta()

    @staticmethod
    def _json_path(response, path: str):
        try:
            value = response.json()
        except Exception:
            return None
        for part in [p for p in path.split(".") if p]:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value

    def _target_allowed(self, url: str) -> bool:
        if self.allow_external_probes:
            return True
        try:
            parsed = urlparse(url)
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
            "mode": self.mode,
            "max_requests": 2,
            "writes_performed": False,
            "allow_external_probes": self.allow_external_probes,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
