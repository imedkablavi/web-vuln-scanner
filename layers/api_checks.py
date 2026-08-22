from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.models import Finding


class APIPostureScanner:
    def __init__(self, config):
        self.config = config
        self.layer_config = config.get("passive_checks", {}).get("api", {})
        self.enabled = bool(self.layer_config.get("enabled", True))
        self.skipped: List[str] = []

    def scan(self, api_engine) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append("API posture checks are disabled by configuration.")
            return [], self._meta(api_engine)

        findings: List[Finding] = []
        swagger = getattr(api_engine, "swagger_inventory", None) or {}
        graphql = getattr(api_engine, "graphql_inventory", None) or {}

        if swagger:
            findings.append(
                Finding(
                    plugin="api_posture",
                    type="OpenAPI Surface Inventory",
                    title="OpenAPI Specification Exposed",
                    category="api-surface",
                    severity="INFO",
                    confidence="HIGH",
                    surface_id=f"api:swagger:{swagger.get('url', '')}",
                    url=swagger.get("url", ""),
                    evidence={
                        "spec_version": swagger.get("spec_version"),
                        "base_url": swagger.get("base_url"),
                        "paths_total": swagger.get("paths_total"),
                        "operations_total": swagger.get("operations_total"),
                        "surfaces_with_inputs": swagger.get("surfaces_with_inputs"),
                        "input_locations": swagger.get("input_locations", {}),
                    },
                    remediation="Restrict public access to internal API specifications if they expose non-public operations.",
                    reproduction={
                        "method": "GET",
                        "url": swagger.get("url", ""),
                    },
                    verification_status="informational",
                    scanner_mode="api-passive",
                    reproducible=True,
                    target={"source": "swagger"},
                )
            )
            unsecured = swagger.get("operations_without_security", [])
            if unsecured:
                findings.append(
                    Finding(
                        plugin="api_posture",
                        type="Undeclared API Security Requirements",
                        title="API Operations Lack Declared Security Requirements",
                        category="api-posture",
                        severity="LOW",
                        confidence="LOW",
                        surface_id=f"api:security:{swagger.get('url', '')}",
                        url=swagger.get("url", ""),
                        evidence={
                            "operations_without_security": unsecured[:15],
                            "total_unsecured": len(unsecured),
                        },
                        remediation="Review OpenAPI security declarations and ensure authenticated operations are annotated consistently.",
                        reproduction={"source": "openapi_spec_review"},
                        verification_status="suspected",
                        scanner_mode="api-passive",
                        reproducible=True,
                        target={"source": "swagger"},
                    )
                )

        if graphql.get("introspection_enabled"):
            findings.append(
                Finding(
                    plugin="api_posture",
                    type="GraphQL Introspection Enabled",
                    title="GraphQL Introspection Available",
                    category="api-posture",
                    severity="LOW",
                    confidence="HIGH",
                    surface_id=f"api:graphql:{graphql.get('url', '')}",
                    url=graphql.get("url", ""),
                    evidence={
                        "types_total": graphql.get("types_total"),
                        "query_fields_total": graphql.get("query_fields_total"),
                        "mutation_fields_total": graphql.get("mutation_fields_total"),
                        "status": graphql.get("status"),
                    },
                    remediation="Disable GraphQL introspection on production deployments when schema visibility is unnecessary.",
                    reproduction={
                        "method": "POST",
                        "url": graphql.get("url", ""),
                        "body": {"query": graphql.get("query")},
                    },
                    verification_status="detected",
                    scanner_mode="api-passive",
                    reproducible=True,
                    target={"source": "graphql"},
                )
            )
            findings.append(
                Finding(
                    plugin="api_posture",
                    type="GraphQL Schema Inventory",
                    title="GraphQL Root Operations Inventoried",
                    category="api-surface",
                    severity="INFO",
                    confidence="HIGH",
                    surface_id=f"api:graphql-schema:{graphql.get('url', '')}",
                    url=graphql.get("url", ""),
                    evidence={
                        "query_fields": graphql.get("query_fields", [])[:25],
                        "mutation_fields": graphql.get("mutation_fields", [])[:25],
                        "query_fields_total": graphql.get("query_fields_total", 0),
                        "mutation_fields_total": graphql.get("mutation_fields_total", 0),
                    },
                    remediation="Review exposed root operations and ensure authorization is enforced in resolvers rather than inferred from schema visibility.",
                    reproduction={"source": "graphql_introspection"},
                    verification_status="informational",
                    scanner_mode="api-passive",
                    reproducible=True,
                    target={"source": "graphql"},
                    notes=[
                        "The presence of mutation fields is inventory information, not a vulnerability by itself."
                    ],
                )
            )

        return findings, self._meta(api_engine)

    def _meta(self, api_engine) -> Dict[str, Any]:
        return {
            "swagger_inventory": getattr(api_engine, "swagger_inventory", None),
            "graphql_inventory": getattr(api_engine, "graphql_inventory", None),
            "errors": getattr(api_engine, "errors", []),
            "skipped": self.skipped,
        }
