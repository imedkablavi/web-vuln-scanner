from __future__ import annotations

from urllib.parse import quote, urljoin

from .models import AttackSurface, InputField
from .scope import ScopePolicy
from .utils import logger


_HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}


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
        return self.scope_policy.is_allowed(
            str(url).split("#", 1)[0], resolve_dns=False
        )

    def _request(self, method, url, **kwargs):
        if self.requester is None:
            raise RuntimeError(
                "APIEngine requires the centralized RequestManager for outbound traffic"
            )
        return self.requester.send(method, url, **kwargs)

    @staticmethod
    def _schema_properties(schema):
        if not isinstance(schema, dict):
            return {}
        properties = schema.get("properties")
        if isinstance(properties, dict):
            return properties
        return {}

    @staticmethod
    def _sample_value(schema, default="TEST_VALUE"):
        if not isinstance(schema, dict):
            return default
        if "example" in schema:
            return schema.get("example")
        if "default" in schema:
            return schema.get("default")
        enum = schema.get("enum")
        if isinstance(enum, list) and enum:
            return enum[0]
        value_type = schema.get("type")
        if value_type in {"integer", "number"}:
            return 1
        if value_type == "boolean":
            return True
        return default

    def _parameter_inputs(self, parameters):
        inputs = []
        for parameter in parameters or []:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            location = str(parameter.get("in", "query") or "query")
            if not name:
                continue
            if location == "body":
                properties = self._schema_properties(parameter.get("schema", {}))
                if properties:
                    for prop_name, prop_schema in properties.items():
                        inputs.append(
                            InputField(
                                name=prop_name,
                                value=self._sample_value(prop_schema),
                                kind="body",
                            )
                        )
                    continue
            schema = parameter.get("schema", parameter)
            inputs.append(
                InputField(
                    name=name,
                    value=self._sample_value(schema),
                    kind=location,
                )
            )
        return inputs

    def _request_body_inputs(self, details):
        request_body = details.get("requestBody", {}) or {}
        content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
        if not isinstance(content, dict):
            return [], []
        content_types = [str(item) for item in content.keys()]
        preferred = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/xml",
            "text/xml",
        ]
        selected = next((item for item in preferred if item in content), None)
        if selected is None and content_types:
            selected = content_types[0]
        if selected is None:
            return [], content_types
        media = content.get(selected, {}) or {}
        schema = media.get("schema", {}) if isinstance(media, dict) else {}
        properties = self._schema_properties(schema)
        inputs = [
            InputField(
                name=name,
                value=self._sample_value(prop_schema),
                kind="body",
            )
            for name, prop_schema in properties.items()
        ]
        return inputs, content_types

    @staticmethod
    def _materialize_path(path, inputs):
        rendered = str(path)
        for item in inputs:
            if item.kind != "path":
                continue
            rendered = rendered.replace(
                "{" + item.name + "}",
                quote(str(item.value or "1"), safe=""),
            )
        return rendered

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
                base_url = (
                    urljoin(swagger_url, server_url) if server_url else swagger_url
                )
                spec_version = spec.get("openapi")
            else:
                base_path = spec.get("basePath", "")
                host = spec.get("host", "")
                scheme = (spec.get("schemes") or ["https"])[0]
                base_url = (
                    f"{scheme}://{host}{base_path}" if host else swagger_url
                )
                spec_version = spec.get("swagger")

            paths = spec.get("paths", {}) or {}
            operations_total = 0
            operations_without_security = []
            discovered = []
            input_locations = {}
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                path_parameters = methods.get("parameters", []) or []
                for method, details in methods.items():
                    if (
                        str(method).lower() not in _HTTP_METHODS
                        or not isinstance(details, dict)
                    ):
                        continue
                    parameter_inputs = self._parameter_inputs(
                        list(path_parameters)
                        + list(details.get("parameters", []) or [])
                    )
                    body_inputs, request_content_types = self._request_body_inputs(details)
                    inputs = parameter_inputs + body_inputs
                    params = {
                        item.name: item.value
                        for item in inputs
                        if item.kind == "query"
                    }
                    rendered_path = self._materialize_path(path, inputs)
                    full_url = urljoin(
                        base_url.rstrip("/") + "/",
                        str(rendered_path).lstrip("/"),
                    )
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
                    for item in inputs:
                        input_locations[item.kind] = input_locations.get(item.kind, 0) + 1

                    if not request_content_types and not spec.get("openapi"):
                        request_content_types = list(
                            details.get("consumes", spec.get("consumes", [])) or []
                        )
                    selected_content_type = (
                        "application/json"
                        if "application/json" in request_content_types
                        else (request_content_types[0] if request_content_types else "")
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
                            "operation_id": details.get("operationId") or "",
                            "security": security,
                            "responses": sorted(
                                (details.get("responses") or {}).keys()
                            ),
                            "request_content_types": request_content_types,
                            "content_type": selected_content_type,
                            "input_names": [item.name for item in inputs],
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
                "input_locations": input_locations,
                "surfaces_with_inputs": sum(
                    1 for surface in discovered if surface.inputs or surface.params
                ),
            }
            logger.info(
                f"Discovered {len(discovered)} API endpoints from Swagger."
            )
            return discovered
        except Exception as exc:
            logger.error(f"Swagger Parsing Error: {exc}")
            self.errors.append(
                {"kind": "swagger", "url": swagger_url, "error": str(exc)}
            )
            return []

    @staticmethod
    def _graphql_type_name(type_info):
        current = type_info if isinstance(type_info, dict) else {}
        wrappers = []
        for _ in range(4):
            kind = current.get("kind")
            name = current.get("name")
            if kind:
                wrappers.append(kind)
            if name:
                return name, wrappers
            current = current.get("ofType") or {}
            if not isinstance(current, dict):
                break
        return "", wrappers

    @classmethod
    def _graphql_fields(cls, root):
        if not isinstance(root, dict):
            return []
        fields = []
        for field in root.get("fields", []) or []:
            if not isinstance(field, dict):
                continue
            args = []
            for arg in field.get("args", []) or []:
                if not isinstance(arg, dict):
                    continue
                type_name, wrappers = cls._graphql_type_name(arg.get("type"))
                args.append(
                    {
                        "name": arg.get("name", ""),
                        "type": type_name,
                        "wrappers": wrappers,
                    }
                )
            fields.append({"name": field.get("name", ""), "args": args})
        return fields

    def scan_graphql(self, endpoint_url):
        """Perform bounded GraphQL schema discovery through RequestManager."""
        introspection_query = """
        query WVSIntrospection {
          __schema {
            queryType {
              name
              fields {
                name
                args { name type { kind name ofType { kind name ofType { kind name } } } }
              }
            }
            mutationType {
              name
              fields {
                name
                args { name type { kind name ofType { kind name ofType { kind name } } } }
              }
            }
            types { name kind }
          }
        }
        """
        logger.info(f"Scanning GraphQL Endpoint: {endpoint_url}")
        try:
            if not self._in_scope(endpoint_url):
                raise RuntimeError("GraphQL URL is outside configured scope")
            resp = self._request(
                "POST",
                endpoint_url,
                json={"query": introspection_query},
                timeout=10,
                allow_redirects=False,
                source="graphql-discovery",
            )
            if resp is not None and resp.status_code == 200 and "__schema" in resp.text:
                payload = (
                    resp.json()
                    if "application/json"
                    in resp.headers.get("content-type", "").lower()
                    else {}
                )
                schema = (
                    payload.get("data", {}).get("__schema", {})
                    if isinstance(payload, dict)
                    else {}
                )
                types = schema.get("types", []) if isinstance(schema, dict) else []
                query_fields = self._graphql_fields(schema.get("queryType", {}))
                mutation_fields = self._graphql_fields(
                    schema.get("mutationType", {})
                )
                self.graphql_inventory = {
                    "url": endpoint_url,
                    "status": resp.status_code,
                    "introspection_enabled": True,
                    "types_total": len(types),
                    "query_fields": query_fields,
                    "mutation_fields": mutation_fields,
                    "query_fields_total": len(query_fields),
                    "mutation_fields_total": len(mutation_fields),
                    "query": introspection_query,
                }
                surface = AttackSurface(
                    url=endpoint_url,
                    method="POST",
                    params={},
                    inputs=[
                        InputField(
                            name="query",
                            value="query WVSProbe { __typename }",
                            kind="body",
                        )
                    ],
                    source="graphql",
                    meta={
                        "introspection": True,
                        "content_type": "application/json",
                        "query_fields": query_fields,
                        "mutation_fields": mutation_fields,
                    },
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
