from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .insertion_points import json_document_from_inputs, mutate_json_inputs


_SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


@dataclass
class MaterializedSurfaceRequest:
    method: str
    params: dict[str, Any]
    data: dict[str, Any] | None
    json: Any
    headers: dict[str, Any]
    cookies: dict[str, Any]
    content_type: str


def _field_value(field) -> Any:
    value = getattr(field, "value", None)
    return "" if value is None else value


def _is_json_content_type(content_type: str) -> bool:
    lowered = str(content_type or "").lower()
    return lowered.startswith("application/json") or "+json" in lowered


def materialize_surface_request(
    surface,
    *,
    auth_headers: dict[str, Any] | None = None,
    cookies: dict[str, Any] | None = None,
    body_mutation_name: str = "",
    body_mutation_path: str = "",
    body_mutation_payload: Any = None,
    mutate_body: bool = False,
) -> MaterializedSurfaceRequest:
    """Build one canonical HTTP request model from an AttackSurface.

    This function performs no network I/O. Baseline and candidate request paths
    should consume the same materialized representation so that response
    comparisons differ only by the selected mutation.
    """

    params = dict(getattr(surface, "params", {}) or {})
    headers = dict(auth_headers or {})
    request_cookies = dict(cookies or {})
    body_inputs = []
    flat_body: dict[str, Any] = {}

    for field in getattr(surface, "inputs", []) or []:
        kind = str(getattr(field, "kind", "") or "").strip().lower()
        value = _field_value(field)
        if kind == "body":
            body_inputs.append(field)
            path = str(getattr(field, "path", "") or "")
            if not path.startswith("/"):
                flat_body[str(getattr(field, "name", "") or "")] = value
        elif kind == "query":
            params[str(getattr(field, "name", "") or "")] = value
        elif kind == "header":
            headers[str(getattr(field, "name", "") or "")] = value
        elif kind == "cookie":
            request_cookies[str(getattr(field, "name", "") or "")] = value

    method = str(getattr(surface, "method", "GET") or "GET").upper()
    if body_inputs and method == "GET":
        method = "POST"
    if method not in _SUPPORTED_METHODS:
        raise ValueError(f"Unsupported surface HTTP method: {method}")

    meta = getattr(surface, "meta", {}) or {}
    content_type = str(meta.get("content_type", "") or "")
    json_payload = None
    form_payload: dict[str, Any] | None = None

    if _is_json_content_type(content_type):
        if mutate_body:
            json_payload = mutate_json_inputs(
                body_inputs,
                name=body_mutation_name,
                path=body_mutation_path,
                payload=body_mutation_payload,
            )
        elif body_inputs:
            json_payload = json_document_from_inputs(body_inputs)
    else:
        if mutate_body:
            if str(body_mutation_path or "").startswith("/"):
                raise ValueError(
                    "Canonical nested body mutation requires a JSON content type"
                )
            flat_body[body_mutation_name] = body_mutation_payload
        form_payload = flat_body or None

    if method in {"GET", "HEAD"}:
        form_payload = None
        json_payload = None

    return MaterializedSurfaceRequest(
        method=method,
        params=params,
        data=form_payload,
        json=json_payload,
        headers=headers,
        cookies=request_cookies,
        content_type=content_type,
    )


def request_shapes_equal(
    left: MaterializedSurfaceRequest,
    right: MaterializedSurfaceRequest,
    *,
    ignore_json_pointer: str = "",
) -> bool:
    """Compare materialized request structure for regression tests/diagnostics.

    The optional pointer argument is intentionally advisory for now; callers
    should compare mutated JSON documents separately when they need leaf-level
    value assertions. This helper focuses on transport shape parity.
    """

    return (
        left.method == right.method
        and left.params == right.params
        and left.data == right.data
        and left.headers == right.headers
        and left.cookies == right.cookies
        and type(left.json) is type(right.json)
        and left.content_type == right.content_type
    )
