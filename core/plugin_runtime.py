from __future__ import annotations

from typing import Optional
from urllib.parse import quote, urlparse, urlunparse

from core.models import AttackSurface
from plugins.base import TestCase


SAFE_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}


def _inject_path(url: str, param: str, payload: str) -> str:
    """Replace an explicit path placeholder only; never guess path locations."""
    parsed = urlparse(url)
    placeholder = "{" + param + "}"
    if placeholder not in parsed.path:
        raise RuntimeError(f"Path testcase requires explicit {placeholder} placeholder")
    path = parsed.path.replace(placeholder, quote(payload, safe=""), 1)
    return urlunparse(parsed._replace(path=path))


def send_surface_bounded(requester, surface: AttackSurface, testcase: Optional[TestCase] = None, timeout: float = 10.0):
    """Dispatch a surface through RequestManager.send with an explicit timeout.

    This is the active-plugin transport. It preserves RequestManager's scope/SSRF,
    retry, rate-limit and concurrency enforcement while preventing plugins from
    calling requests directly or silently expanding target scope.
    """
    base_params = dict(surface.params)
    base_data = {}
    base_headers = requester.config.get("auth", {}).get("headers", {}).copy()
    base_cookies = dict(getattr(requester, "cookies", {}) or {})
    has_body_inputs = False

    for field in surface.inputs:
        if field.kind == "body":
            has_body_inputs = True
            base_data[field.name] = field.value or ""
        elif field.kind == "query":
            base_params[field.name] = field.value or ""
        elif field.kind == "header":
            base_headers[field.name] = field.value or ""
        elif field.kind == "cookie":
            base_cookies[field.name] = field.value or ""

    target_url = surface.url
    method = surface.method.upper()
    if testcase is not None:
        if testcase.kind == "query":
            base_params[testcase.param] = testcase.payload
        elif testcase.kind == "body":
            has_body_inputs = True
            base_data[testcase.param] = testcase.payload
        elif testcase.kind == "header":
            base_headers[testcase.param] = testcase.payload
        elif testcase.kind == "cookie":
            base_cookies[testcase.param] = testcase.payload
        elif testcase.kind == "path":
            target_url = _inject_path(target_url, testcase.param, testcase.payload)
        else:
            raise RuntimeError(f"Unsupported testcase kind: {testcase.kind}")
        if testcase.method_override:
            method = testcase.method_override.upper()

    if has_body_inputs and method == "GET":
        method = "POST"
    if method not in SAFE_METHODS:
        raise RuntimeError(f"Unsupported HTTP method for plugin runtime: {method}")

    json_payload = None
    if surface.meta.get("content_type", "").startswith("application/json"):
        json_payload = base_data
        base_data = None

    return requester.send(
        method=method,
        url=target_url,
        params=base_params if method == "GET" else None,
        data=base_data if method != "GET" else None,
        json=json_payload,
        headers=base_headers or None,
        cookies=base_cookies,
        timeout=timeout,
        actor_id="",
        source=surface.source,
    )
