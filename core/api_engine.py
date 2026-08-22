from __future__ import annotations

from urllib.parse import urljoin

from .models import AttackSurface, InputField
from .scope import ScopePolicy
from .utils import logger


_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


class APIEngine:
    def __init__(self, config, requester=None):
        self.config = config
        self.endpoints = []
        self.requester = requester
        self.scope_policy = getattr(requester, "scope_policy", None) or ScopePolicy(config)
        self.errors = []
        self.swagger_inventory = None
        self.graphql_inventory = None

    def _in_scope(self, url):
        return self.scope_policy.is_allowed(str(url).split("#", 1)[0], resolve_dns=False)

    def _request(self, method, url, **kwargs):
        if self.requester is None:
            raise RuntimeError(
                "APIEngine requires the centralized RequestManager for outbound traffic"
            )
        return self.requester.send(method, url, **kwargs)

    def load_swagger(self, swagger_url):
        """Parse an authorized Swagger/OpenAPI document through RequestManager."""
        logger.info(f"Parsing Swagger: {swagger_url}")
        try:
            if not self._in_scope(swagger_url):
                raise RuntimeError("Swagger URL is outside configured scope")
            resp = self._request("GET", swagger_url, timeout=10)
            if resp is None or resp.status_code != 200:
                logger.error("Failed to fetch Swagger file")
                return []

            spec = resp.json()
            if spec.get("openapi"):
                servers = spec.get("servers") or []
                server_url = servers[0].get("url", "") if servers else ""
                base_url = urljoin(swagger_url, server_url) if server_url else swagger_url
                spec_version = spec.get("openapi")
            else:
                base_path = spec.get("basePath", "")
                host = spec.get("host", "")
                scheme = (spec.get("schemes") or ["https"])[0]
                base_url = f"{scheme}://{host}{base_path}" if host else swagger_url
                spec_version = spec.get("swagger")

            paths = spec.get("paths", {}) or {}
            operations_total = 0
            operations_without_security = []
            discovered = []
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                path_parameters = methods.get("parameters", []) or []
                for method, details in methods.items():
                    if str(method).lower() not in _HTTP_METHODS or not isinstance(details, dict):
                        continue
                    params = {}
                    inputs = []
                    for parameter in list(path_parameters) + list(details.get("parameters", []) or []):
                        if not isinstance(parameter, dict):
                            continue
                        name = parameter.get("name")
                        location = parameter.get("in", "query")
                        if not name:
                            continue
                        params[name] = "TEST_VALUE"
                        inputs.append(
                            InputField(
                                name=name,
                                value="TEST_VALUE",
                                kind=location,
                            )
                        )

                    full_url = urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
                    if not self._in_scope(full_url):
                        continue
                    operations_total += 1
                    security = details.get("security", spec.get("security", []))
                    if not security:
                        operations_without_security.append(
                            {
                                "method": method.upper(),
                                "path": path,
                                "summary": details.get("summary")
                                or details.get("operationId")
                                or "",
                            }
                        )
                    surface = AttackSurface(
                        url=full_url,
                        method=method.upper(),
                        params=params,
                        inputs=inputs,
                        source="swagger",
                        meta={
                            "path": path,
                            "summary": details.get("summary")
                            or details.get("operationId")
                            or "",
                            "security": security,
                            "responses": sorted((details.get("responses") or {}).keys()),
                        },
                    )
                    self.endpoints.append(surface)
                    discovered.append(surface)

            self.swagger_inventory = {
                "url": swagger_url,
                "spec_version": spec_version,
                "base_url": base_url,
                "paths_total": len(paths),
                "operations_total": operations_total,
                "operations_without_security": operations_without_security,
            }
            logger.info(f"Discovered {len(discovered)} API endpoints from Swagger.")
            return discovered
        except Exception as exc:
            logger.error(f"Swagger Parsing Error: {exc}")
            self.errors.append(
                {"kind": "swagger", "url": swagger_url, "error": str(exc)}
            )
            return []

    def scan_graphql(self, endpoint_url):
        """Perform explicit GraphQL introspection through RequestManager."""
        introspection_query = """
        query {
          __schema {
            types {
              name
              fields { name }
            }
          }
        }
        """
        logger.info(f"Scanning GraphQL Endpoint: {endpoint_url}")
        try:
            if not self._in_scope(endpoint_url):
                raise RuntimeError("GraphQL URL is outside configured scope")
            resp = self._request(
                "POST", endpoint_url, json={"query": introspection_query}, timeout=10
            )
            if resp is not None and resp.status_code == 200 and "__schema" in resp.text:
                payload = (
                    resp.json()
                    if "application/json" in resp.headers.get("content-type", "")
                    else {}
                )
                types = (
                    payload.get("data", {}).get("__schema", {}).get("types", [])
                    if isinstance(payload, dict)
                    else []
                )
                self.graphql_inventory = {
                    "url": endpoint_url,
                    "status": resp.status_code,
                    "introspection_enabled": True,
                    "types_total": len(types),
                    "query": introspection_query,
                }
                surface = AttackSurface(
                    url=endpoint_url,
                    method="POST",
                    params={},
                    inputs=[
                        InputField(
                            name="query",
                            value=introspection_query,
                            kind="body",
                        )
                    ],
                    source="graphql",
                    meta={"introspection": True},
                )
                self.endpoints.append(surface)
                return [surface]
        except Exception as exc:
            logger.error(f"GraphQL Scan Error: {exc}")
            self.errors.append(
                {"kind": "graphql", "url": endpoint_url, "error": str(exc)}
            )
        return []

    def get_endpoints(self):
        return self.endpoints
