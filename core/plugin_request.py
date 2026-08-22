from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

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

    # Third-party/fixture request adapters written against the older scanner
    # contract may only expose send_surface(). Preserve query/body behavior for
    # those adapters, while requiring the real RequestManager contract for
    # header, cookie, path, method-override, and redirect-aware test cases.
    if not hasattr(requester, "send_as_actor"):
        legacy_supported = (
            kind in {"query", "body"}
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
    has_body_inputs = False

    for field in getattr(surface, "inputs", []) or []:
        field_kind = str(field.kind or "").lower()
        if field_kind == "body":
            has_body_inputs = True
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
    elif kind == "body":
        data[name] = payload
        has_body_inputs = True
    elif kind == "header":
        headers[name] = payload
    elif kind == "cookie":
        cookies[name] = payload
    elif kind == "path":
        target_url = _inject_path(target_url, surface, name, payload)

    override = str(getattr(testcase, "method_override", "") or "").upper()
    method = override or str(surface.method or "GET").upper()
    if not override and has_body_inputs and method == "GET":
        method = "POST"
    if method not in _SUPPORTED_METHODS:
        raise ValueError(f"Unsupported plugin HTTP method: {method}")

    content_type = str(
        (getattr(surface, "meta", {}) or {}).get("content_type", "")
    ).lower()
    json_payload = data if content_type.startswith("application/json") else None
    form_payload = None if json_payload is not None else data

    logger.debug(
        "Plugin request %s %s input=%s:%s",
        method,
        target_url,
        kind,
        name,
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
