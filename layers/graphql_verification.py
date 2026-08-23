from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from core.models import Finding


INTROSPECTION_QUERY = "query ScannerIntrospection { __schema { queryType { name } types { name } } }"
INVALID_FIELD_QUERY = "query ScannerInvalid { scannerDefinitelyMissingField }"


class GraphQLVerifier:
    """Bounded GraphQL-specific verification without mutations or depth abuse."""

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        self.config = config
        layer = config.get("active_verification", {}).get("graphql", {})
        self.enabled = bool(layer.get("enabled", True))
        self.max_requests = max(0, min(int(layer.get("max_requests", 2)), 2))
        self.errors: List[Dict[str, Any]] = []
        self.observations: Dict[str, Any] = {}

    def scan(self, endpoint_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled or not endpoint_url:
            reason = "GraphQL verification disabled." if not self.enabled else "No GraphQL endpoint configured."
            return [], self._meta(skipped=reason)
        findings: List[Finding] = []
        remaining = self.max_requests

        if remaining > 0:
            intro = self._post(endpoint_url, INTROSPECTION_QUERY, "introspection")
            remaining -= 1
            if intro is not None:
                self.observations["introspection"] = {
                    "status": intro["status"],
                    "enabled": bool(intro["payload"].get("data", {}).get("__schema")) if isinstance(intro["payload"], dict) else False,
                }

        if remaining > 0:
            invalid = self._post(endpoint_url, INVALID_FIELD_QUERY, "invalid-field")
            remaining -= 1
            if invalid is not None:
                signals = self._debug_signals(invalid["payload"], invalid["text"])
                self.observations["invalid_field"] = {
                    "status": invalid["status"],
                    "debug_signals": signals,
                }
                if signals:
                    findings.append(
                        Finding(
                            plugin="graphql_verification",
                            type="GraphQL Verbose Error Disclosure",
                            title="GraphQL Errors Expose Internal Debug Details",
                            category="api-posture",
                            severity="MEDIUM",
                            confidence="HIGH",
                            surface_id=f"graphql-debug:{endpoint_url}",
                            url=endpoint_url,
                            evidence={
                                "status": invalid["status"],
                                "signals": signals,
                                "probe": "invalid field validation query",
                            },
                            remediation="Return generic GraphQL errors to clients and keep stack traces, exception objects, filesystem paths, and debug extensions server-side.",
                            reproduction={
                                "method": "POST",
                                "body_class": "non-mutating-invalid-field-query",
                                "request_count": 1,
                            },
                            verification_status="verified",
                            scanner_mode="active-bounded",
                            reproducible=True,
                            target={"source": "graphql"},
                        )
                    )
        return findings, self._meta()

    def _post(self, endpoint_url: str, query: str, kind: str):
        try:
            response = self.requester.send("POST", endpoint_url, json={"query": query})
        except Exception as exc:
            self.errors.append({"kind": kind, "url": endpoint_url, "error": str(exc)})
            return None
        if response is None:
            self.errors.append({"kind": kind, "url": endpoint_url, "error": "empty_response"})
            return None
        text = response.text or ""
        payload: Dict[str, Any] = {}
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(text)
            except Exception:
                payload = {}
        return {"status": response.status_code, "payload": payload, "text": text}

    def _debug_signals(self, payload: Any, raw_text: str) -> List[str]:
        signals = set()
        sensitive_keys = {"stacktrace", "stack_trace", "traceback", "exception", "debug", "file", "filepath"}

        def walk(value: Any, path: str = ""):
            if isinstance(value, dict):
                for key, child in value.items():
                    key_text = str(key).lower()
                    child_path = f"{path}.{key_text}" if path else key_text
                    if key_text in sensitive_keys:
                        signals.add(f"debug-key:{child_path}")
                    walk(child, child_path)
            elif isinstance(value, list):
                for index, child in enumerate(value[:20]):
                    walk(child, f"{path}[{index}]")
            elif isinstance(value, str):
                lowered = value.lower()
                if "traceback (most recent call last)" in lowered or "stack trace" in lowered:
                    signals.add("stack-trace-text")
                if re.search(r"(?:^|\s)/(?:srv|app|home|var|opt)/[^\s]+\.(?:py|js|ts|rb|php|java)(?::\d+)?", value):
                    signals.add("server-file-path")
                if re.search(r"\b(?:runtimeerror|valueerror|typeerror|exception)\b", lowered):
                    signals.add("exception-class")

        walk(payload)
        if "traceback (most recent call last)" in (raw_text or "").lower():
            signals.add("stack-trace-text")
        return sorted(signals)

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_requests": self.max_requests,
            "observations": self.observations,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
