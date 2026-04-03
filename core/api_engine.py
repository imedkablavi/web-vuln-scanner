import requests
from urllib.parse import urljoin
from .utils import logger
from .models import AttackSurface, InputField

class APIEngine:
    def __init__(self, config, requester=None):
        self.config = config
        self.endpoints = []
        self.requester = requester
        scope = config.get("scope", {})
        self.include_domains = scope.get("include_domains", [])
        self.exclude_paths = scope.get("exclude_paths", [])
        self.max_url_length = config.get("crawler", {}).get("max_url_length", 2048)
        self.errors = []
        self.swagger_inventory = None
        self.graphql_inventory = None

    def _in_scope(self, url):
        parsed = urljoin(url, "").split("#")[0]
        from urllib.parse import urlparse
        p = urlparse(parsed)
        if p.scheme not in ("http", "https"):
            return False
        if len(parsed) > self.max_url_length:
            return False
        for ep in self.exclude_paths:
            if p.path.startswith(ep):
                return False
        if self.include_domains:
            host = p.netloc
            allowed = False
            for dom in self.include_domains:
                if dom.startswith("*.") and host.endswith(dom[2:]):
                    allowed = True
                elif host == dom:
                    allowed = True
            if not allowed:
                return False
        return True

    def load_swagger(self, swagger_url):
        """Parses a Swagger/OpenAPI JSON file."""
        logger.info(f"Parsing Swagger: {swagger_url}")
        try:
            if self.requester:
                resp = self.requester.send("GET", swagger_url, timeout=10)
            else:
                resp = requests.get(swagger_url, timeout=10)
            if resp is None or resp.status_code != 200:
                logger.error("Failed to fetch Swagger file")
                return []

            spec = resp.json()
            if spec.get("openapi"):
                servers = spec.get("servers") or []
                base_url = servers[0].get("url", swagger_url) if servers else swagger_url
                spec_version = spec.get("openapi")
            else:
                base_path = spec.get("basePath", "")
                host = spec.get("host", "")
                scheme = spec.get("schemes", ["https"])[0]
                base_url = f"{scheme}://{host}{base_path}" if host else swagger_url
                spec_version = spec.get("swagger")

            paths = spec.get("paths", {})
            operations_total = 0
            operations_without_security = []
            for path, methods in paths.items():
                for method, details in methods.items():
                    if not isinstance(details, dict):
                        continue
                    params = {}
                    inputs = []
                    for p in details.get("parameters", []):
                        name = p.get("name")
                        location = p.get("in", "query")
                        if not name:
                            continue
                        params[name] = "TEST_VALUE"
                        inputs.append(InputField(name=name, value="TEST_VALUE", kind=location))

                    full_url = urljoin(base_url, path)
                    if not self._in_scope(full_url):
                        continue
                    operations_total += 1
                    security = details.get("security", spec.get("security", []))
                    if not security:
                        operations_without_security.append({
                            "method": method.upper(),
                            "path": path,
                            "summary": details.get("summary") or details.get("operationId") or "",
                        })
                    self.endpoints.append(
                        AttackSurface(
                            url=full_url,
                            method=method.upper(),
                            params=params,
                            inputs=inputs,
                            source="swagger",
                            meta={
                                "path": path,
                                "summary": details.get("summary") or details.get("operationId") or "",
                                "security": security,
                                "responses": sorted((details.get("responses") or {}).keys()),
                            },
                        )
                    )

            self.swagger_inventory = {
                "url": swagger_url,
                "spec_version": spec_version,
                "base_url": base_url,
                "paths_total": len(paths),
                "operations_total": operations_total,
                "operations_without_security": operations_without_security,
            }
            logger.info(f"Discovered {len(self.endpoints)} API endpoints from Swagger.")
            return self.endpoints

        except Exception as e:
            logger.error(f"Swagger Parsing Error: {e}")
            self.errors.append({"kind": "swagger", "url": swagger_url, "error": str(e)})
            return []

    def scan_graphql(self, endpoint_url):
        """
        Performs GraphQL Introspection and basic checks.
        """
        logger.info(f"Scanning GraphQL Endpoint: {endpoint_url}")
        introspection_query = """
        query {
          __schema {
            types {
              name
              fields {
                name
              }
            }
          }
        }
        """
        try:
            if self.requester:
                resp = self.requester.send("POST", endpoint_url, json={"query": introspection_query}, timeout=10)
            else:
                resp = requests.post(endpoint_url, json={"query": introspection_query}, timeout=10)
            if resp is not None and resp.status_code == 200 and "__schema" in resp.text:
                logger.info("GraphQL Introspection Enabled! (Information Disclosure)")
                payload = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                types = payload.get("data", {}).get("__schema", {}).get("types", []) if isinstance(payload, dict) else []
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
                    inputs=[InputField(name="query", value=introspection_query, kind="body")],
                    source="graphql",
                    meta={"introspection": True},
                )
                if self._in_scope(endpoint_url):
                    self.endpoints.append(surface)
                    return [surface]
        except Exception as e:
            logger.error(f"GraphQL Scan Error: {e}")
            self.errors.append({"kind": "graphql", "url": endpoint_url, "error": str(e)})
        return []

    def get_endpoints(self):
        return self.endpoints
