from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

from .insertion_points import json_document_from_inputs, mutate_json_inputs
from .utils import logger


_SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_SUPPORTED_KINDS = {"query", "body", "header", "cookie", "path"}


def _inject_path(url: str, surface, name: str, payload: str) -> str:
    parsed = urlsplit(url)
    encoded = quote(str(payload), safe="")
    placeholder = "{" + str(name) + "}"
    path = parsed.path or "/"
    if placeholder in path:
        path = path.replace(placeholder, encoded, 1)
        return urlunsplit(
            (parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment)
        )

    original = ""
    for field in getattr(surface, "inputs", []) or []:
        if field.name == name and field.kind == "path":
            original = str(field.value or "")
            break
    if original:
        parts = path.split("/")
        for index, part in enumerate(parts):
            if part == original:
                parts[index] = encoded
                path = "/".join(parts)
                return urlunsplit(
                    (parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment)
                )
    raise ValueError(
        f"Cannot inject path parameter '{name}' because no matching path segment was discovered"
    )


def send_plugin_test(requester, surface, testcase, *, actor=None, replay_of=""):
    """Send one plugin TestCase through RequestManager with kind-aware injection."""

    kind = str(getattr(testcase, "kind", "") or "").strip().lower()
    if kind not in _SUPPORTED_KINDS:
        raise ValueError(f"Unsupported plugin input kind: {kind or '<missing>'}")

    payload = getattr(testcase, "payload", "")
    name = str(getattr(testcase, "param", "") or "")
    input_path = str(getattr(testcase, "input_path", "") or "")

    # Third-party/fixture request adapters written against the older scanner
    # contract may only expose send_surface(). Preserve flat query/body behavior
    # for those adapters. Canonical nested paths require RequestManager.
    if not hasattr(requester, "send_as_actor"):
        legacy_supported = (
            kind in {"query", "body"}
            and not input_path.startswith("/")
            and not getattr(testcase, "method_override", None)
            and getattr(testcase, "allow_redirects", None) is None
            and hasattr(requester, "send_surface")
        )
        if legacy_supported:
            return requester.send_surface(surface, name, payload)
        raise RuntimeError(
            "This plugin test requires a RequestManager-compatible send_as_actor() implementation"
        )

    params = dict(getattr(surface, "params", {}) or {})
    data = {}
    requester_config = getattr(requester, "config", {}) or {}
    headers = dict(requester_config.get("auth", {}).get("headers", {}) or {})
    cookies = dict(getattr(requester, "cookies", {}) or {})
    body_inputs = []

    for field in getattr(surface, "inputs", []) or []:
        field_kind = str(field.kind or "").lower()
        if field_kind == "body":
            body_inputs.append(field)
            if not str(getattr(field, "path", "") or "").startswith("/"):
                data[field.name] = field.value if field.value is not None else ""
        elif field_kind == "query":
            params[field.name] = field.value if field.value is not None else ""
        elif field_kind == "header":
            headers[field.name] = field.value if field.value is not None else ""
        elif field_kind == "cookie":
            cookies[field.name] = field.value if field.value is not None else ""

    target_url = surface.url
    if kind == "query":
        params[name] = payload
    elif kind == "header":
        headers[name] = payload
    elif kind == "cookie":
        cookies[name] = payload
    elif kind == "path":
        target_url = _inject_path(target_url, surface, name, payload)

    override = str(getattr(testcase, "method_override", "") or "").upper()
    method = override or str(surface.method or "GET").upper()
    if not override and body_inputs and method == "GET":
        method = "POST"
    if method not in _SUPPORTED_METHODS:
        raise ValueError(f"Unsupported plugin HTTP method: {method}")

    content_type = str(
        (getattr(surface, "meta", {}) or {}).get("content_type", "")
    ).lower()
    is_json = content_type.startswith("application/json") or "+json" in content_type

    json_payload = None
    form_payload = None
    if is_json:
        if kind == "body":
            json_payload = mutate_json_inputs(
                body_inputs,
                name=name,
                path=input_path,
                payload=payload,
            )
        elif body_inputs:
            json_payload = json_document_from_inputs(body_inputs)
    else:
        if kind == "body":
            data[name] = payload
        form_payload = data or None

    logger.debug(
        "Plugin request %s %s input=%s:%s path=%s",
        method,
        target_url,
        kind,
        name,
        input_path,
    )
    return requester.send_as_actor(
        method,
        target_url,
        actor=actor,
        params=params or None,
        data=form_payload if method not in {"GET", "HEAD"} else None,
        json=json_payload if method not in {"GET", "HEAD"} else None,
        headers=headers or None,
        cookies=cookies or None,
        timeout=getattr(requester, "timeout", None),
        allow_redirects=getattr(testcase, "allow_redirects", None),
        source=f"{surface.source}:{getattr(testcase, 'plugin', 'plugin')}",
        replay_of=replay_of,
    )
