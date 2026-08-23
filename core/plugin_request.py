from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

from .request_materializer import materialize_surface_request
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

    requester_config = getattr(requester, "config", {}) or {}
    materialized = materialize_surface_request(
        surface,
        auth_headers=dict(requester_config.get("auth", {}).get("headers", {}) or {}),
        cookies=dict(getattr(requester, "cookies", {}) or {}),
        body_mutation_name=name,
        body_mutation_path=input_path,
        body_mutation_payload=payload,
        mutate_body=(kind == "body"),
    )

    target_url = surface.url
    params = dict(materialized.params)
    headers = dict(materialized.headers)
    cookies = dict(materialized.cookies)
    form_payload = materialized.data
    json_payload = materialized.json

    if kind == "query":
        params[name] = payload
    elif kind == "header":
        headers[name] = payload
    elif kind == "cookie":
        cookies[name] = payload
    elif kind == "path":
        target_url = _inject_path(target_url, surface, name, payload)

    override = str(getattr(testcase, "method_override", "") or "").upper()
    method = override or materialized.method
    if method not in _SUPPORTED_METHODS:
        raise ValueError(f"Unsupported plugin HTTP method: {method}")
    if method in {"GET", "HEAD"}:
        form_payload = None
        json_payload = None

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
        data=form_payload,
        json=json_payload,
        headers=headers or None,
        cookies=cookies or None,
        timeout=getattr(requester, "timeout", None),
        allow_redirects=getattr(testcase, "allow_redirects", None),
        source=f"{surface.source}:{getattr(testcase, 'plugin', 'plugin')}",
        replay_of=replay_of,
    )
