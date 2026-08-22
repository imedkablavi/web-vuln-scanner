from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .insertion_points import body_inputs_from_raw, json_value_inputs
from .models import AttackSurface, InputField
from .scope import ScopePolicy


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
_VARIABLE_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_PATH_VARIABLE_RE = re.compile(r"(?<=/):[A-Za-z_][A-Za-z0-9_.-]*")


def _safe_sample(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return 1
    if isinstance(value, float):
        return 1.0
    if value is None:
        return None
    return "TEST_VALUE"


def _sanitize_input_values(inputs: Iterable[InputField]) -> list[InputField]:
    return [
        InputField(
            name=item.name,
            value=_safe_sample(item.value),
            kind=item.kind,
            path=item.path,
            data_type=item.data_type,
            required=item.required,
        )
        for item in inputs or []
    ]


def _target_base(target: str) -> str:
    parsed = urlsplit(str(target or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target must not contain embedded credentials")
    netloc = parsed.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def _scope_for_target(target: str, *, allow_private: bool = False) -> ScopePolicy:
    base = _target_base(target)
    parsed = urlsplit(base)
    return ScopePolicy(
        {
            "target": base,
            "scope": {
                "allowlist": [parsed.netloc],
                "include_domains": [parsed.netloc],
                "exclude_paths": [],
                "allow_private": bool(allow_private),
                "resolve_dns": False,
            },
            "crawler": {"max_url_length": 4096},
            "concurrency": {"global_timeout_seconds": 60},
        }
    )


def _collection_variables(data: dict[str, Any]) -> dict[str, str]:
    variables: dict[str, str] = {}
    for item in data.get("variable", []) or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", item.get("id", "")) or "").strip()
        value = item.get("value")
        if key and value is not None:
            variables[key] = str(value)
    return variables


def _replace_variables(raw: str, *, target: str, variables: dict[str, str]) -> str:
    target_parts = urlsplit(_target_base(target))
    target_origin = urlunsplit((target_parts.scheme, target_parts.netloc, "", "", ""))

    def replace(match: re.Match[str]) -> str:
        name = match.group(1).strip()
        lowered = name.lower()
        # Base URL variables are common in Postman. Pin them to the explicit
        # authorized target instead of trusting a collection-stored URL.
        if any(token in lowered for token in ("baseurl", "base_url", "host", "origin")):
            return target_origin
        value = variables.get(name)
        # Never copy collection secrets into scanner artifacts or requests. URL
        # variables become structure-preserving placeholders.
        if value is not None and value.lower().startswith(("http://", "https://")):
            return target_origin
        return "1"

    rendered = _VARIABLE_RE.sub(replace, str(raw or ""))
    rendered = _PATH_VARIABLE_RE.sub("1", rendered)
    return rendered


def _request_url(url_value: Any, *, target: str, variables: dict[str, str]) -> str:
    raw = ""
    if isinstance(url_value, str):
        raw = url_value
    elif isinstance(url_value, dict):
        raw = str(url_value.get("raw", "") or "")
        if not raw:
            protocol = str(url_value.get("protocol", "") or "")
            host = url_value.get("host") or []
            if isinstance(host, list):
                host = ".".join(str(item) for item in host)
            path = url_value.get("path") or []
            if isinstance(path, list):
                parts = []
                for item in path:
                    if isinstance(item, dict):
                        parts.append(str(item.get("value", "1") or "1"))
                    else:
                        parts.append(str(item))
                path = "/".join(parts)
            port = str(url_value.get("port", "") or "")
            netloc = str(host or "") + (f":{port}" if port else "")
            if protocol and netloc:
                raw = f"{protocol}://{netloc}/{str(path).lstrip('/')}"
    raw = _replace_variables(raw, target=target, variables=variables).strip()
    if not raw:
        raise ValueError("request URL is missing")
    if raw.startswith("/"):
        raw = urljoin(_target_base(target), raw)
    if not raw.lower().startswith(("http://", "https://")):
        raw = urljoin(_target_base(target).rstrip("/") + "/", raw)
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("request URL is not an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("request URL contains embedded credentials")
    netloc = parsed.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    # Query values and fragments are intentionally discarded. Query names are
    # represented separately as insertion points.
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def _query_inputs(request: dict[str, Any], raw_url: str) -> tuple[dict[str, str], list[InputField]]:
    names: list[str] = []
    url_value = request.get("url")
    if isinstance(url_value, dict):
        for item in url_value.get("query", []) or []:
            if not isinstance(item, dict) or item.get("disabled", False):
                continue
            name = str(item.get("key", "") or "").strip()
            if name:
                names.append(name)
    try:
        names.extend(name for name, _ in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True) if name)
    except ValueError:
        pass
    deduped = list(dict.fromkeys(names))
    return (
        {name: "" for name in deduped},
        [InputField(name=name, value="", kind="query", path=name, data_type="string") for name in deduped],
    )


def _content_type(request: dict[str, Any]) -> str:
    for item in request.get("header", []) or []:
        if not isinstance(item, dict) or item.get("disabled", False):
            continue
        if str(item.get("key", "") or "").strip().lower() == "content-type":
            return str(item.get("value", "") or "").split(";", 1)[0].strip().lower()
    return ""


def _header_names(request: dict[str, Any]) -> list[str]:
    names = []
    for item in request.get("header", []) or []:
        if not isinstance(item, dict) or item.get("disabled", False):
            continue
        name = str(item.get("key", "") or "").strip()
        if name and name.lower() not in _SENSITIVE_HEADERS:
            names.append(name)
    return sorted(set(names), key=str.lower)


def _body_inputs(request: dict[str, Any], *, max_body_points: int) -> tuple[list[InputField], str, str]:
    body = request.get("body") or {}
    if not isinstance(body, dict):
        return [], "", ""
    mode = str(body.get("mode", "") or "").strip().lower()
    content_type = _content_type(request)
    inputs: list[InputField] = []

    if mode == "raw":
        raw = str(body.get("raw", "") or "")
        language = str(
            ((body.get("options") or {}).get("raw") or {}).get("language", "")
            if isinstance(body.get("options"), dict)
            else ""
        ).lower()
        inferred = content_type
        if not inferred and language == "json":
            inferred = "application/json"
        elif not inferred and language in {"xml", "html"}:
            inferred = "application/xml" if language == "xml" else "text/html"
        inputs = body_inputs_from_raw(
            raw,
            content_type=inferred,
            mode=language,
            max_points=max_body_points,
        )
        return _sanitize_input_values(inputs), inferred, language or "raw"

    if mode in {"urlencoded", "formdata"}:
        raw_items = body.get(mode, []) or []
        for item in raw_items:
            if len(inputs) >= max_body_points:
                break
            if not isinstance(item, dict) or item.get("disabled", False):
                continue
            name = str(item.get("key", "") or "").strip()
            if not name:
                continue
            if mode == "formdata" and str(item.get("type", "text") or "text").lower() == "file":
                continue
            inputs.append(
                InputField(
                    name=name,
                    value="TEST_VALUE",
                    kind="body",
                    path=name,
                    data_type="string",
                )
            )
        inferred = content_type or (
            "multipart/form-data" if mode == "formdata" else "application/x-www-form-urlencoded"
        )
        return inputs, inferred, mode

    if mode == "graphql":
        graphql = body.get("graphql") or {}
        variables = graphql.get("variables") if isinstance(graphql, dict) else None
        if isinstance(variables, str):
            try:
                variables = json.loads(variables)
            except (TypeError, ValueError, json.JSONDecodeError):
                variables = None
        if isinstance(variables, (dict, list)):
            raw_points = json_value_inputs(
                {"variables": variables},
                max_points=max_body_points,
            )
            inputs = _sanitize_input_values(raw_points)
        return inputs, content_type or "application/json", "graphql"

    return [], content_type, mode


def _iter_items(items: Iterable[Any], folder: tuple[str, ...] = ()):
    for item in items or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if isinstance(item.get("request"), (dict, str)):
            yield folder, item
        child_items = item.get("item")
        if isinstance(child_items, list):
            yield from _iter_items(child_items, folder + ((name or "folder"),))


def import_postman_data(
    data: dict[str, Any],
    *,
    target: str,
    scope: ScopePolicy | None = None,
    allow_private: bool = False,
    max_requests: int = 5000,
    max_body_points: int = 200,
    active_tests: bool = False,
    allow_state_changing_methods: bool = False,
) -> Tuple[list[AttackSurface], Dict[str, Any]]:
    if not isinstance(data, dict):
        raise ValueError("Postman collection must be a JSON object")
    if isinstance(data.get("collection"), dict):
        data = data["collection"]
    if not isinstance(data.get("item"), list):
        raise ValueError("Postman collection is missing item[]")
    if max_requests <= 0:
        raise ValueError("max_requests must be > 0")
    if max_body_points <= 0:
        raise ValueError("max_body_points must be > 0")

    scope = scope or _scope_for_target(target, allow_private=allow_private)
    variables = _collection_variables(data)
    collection_name = str((data.get("info") or {}).get("name", "") or "")
    schema_url = str((data.get("info") or {}).get("schema", "") or "")
    surfaces: list[AttackSurface] = []
    seen = set()
    skipped = {
        "out_of_scope": 0,
        "unsupported": 0,
        "duplicate": 0,
        "truncated": 0,
    }
    requests_seen = 0

    for folder, item in _iter_items(data.get("item") or []):
        if requests_seen >= max_requests:
            skipped["truncated"] += 1
            break
        requests_seen += 1
        request = item.get("request")
        if isinstance(request, str):
            request = {"method": "GET", "url": request}
        if not isinstance(request, dict):
            skipped["unsupported"] += 1
            continue
        method = str(request.get("method", "GET") or "GET").upper()
        if method not in _ALLOWED_METHODS:
            skipped["unsupported"] += 1
            continue

        raw_url_value = request.get("url")
        raw_url = (
            raw_url_value
            if isinstance(raw_url_value, str)
            else str((raw_url_value or {}).get("raw", "") or "")
        )
        try:
            url = _request_url(raw_url_value, target=target, variables=variables)
        except ValueError:
            skipped["unsupported"] += 1
            continue
        if not scope.is_allowed(url, resolve_dns=False):
            skipped["out_of_scope"] += 1
            continue

        params, query_inputs = _query_inputs(request, _replace_variables(str(raw_url or ""), target=target, variables=variables))
        body_inputs, content_type, body_format = _body_inputs(
            request,
            max_body_points=max_body_points,
        )
        inputs = query_inputs + body_inputs
        active_eligible = bool(active_tests)
        if method in _STATE_CHANGING_METHODS and not allow_state_changing_methods:
            active_eligible = False
        if method == "DELETE":
            active_eligible = False
        if body_format in {"graphql", "xml"}:
            # Inventory these structured formats now; specialized active
            # mutation is added separately to avoid malformed or stateful probes.
            active_eligible = False

        surface = AttackSurface(
            url=url,
            method=method,
            params=params,
            inputs=inputs,
            source="postman",
            meta={
                "postman": True,
                "collection_name": collection_name,
                "item_name": str(item.get("name", "") or ""),
                "folder_path": list(folder),
                "schema": schema_url,
                "content_type": content_type,
                "body_format": body_format,
                "observed_header_names": _header_names(request),
                "active_eligible": active_eligible,
                "sanitized": True,
                "original_values_retained": False,
                "input_paths": [field.path or field.name for field in inputs],
            },
        )
        if surface.id in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(surface.id)
        surfaces.append(surface)

    return surfaces, {
        "source": "postman",
        "collection_name": collection_name,
        "schema": schema_url,
        "requests_seen": requests_seen,
        "surfaces": len(surfaces),
        "surfaces_with_inputs": sum(1 for item in surfaces if item.inputs or item.params),
        "input_points": sum(len(item.inputs) + len(item.params) for item in surfaces),
        "active_eligible": sum(1 for item in surfaces if item.meta.get("active_eligible", False)),
        "skipped": skipped,
        "max_requests": max_requests,
        "max_body_points": max_body_points,
        "sanitized": True,
        "replayed_requests": 0,
    }


def import_postman_file(
    path: str | Path,
    *,
    target: str,
    scope: ScopePolicy | None = None,
    allow_private: bool = False,
    max_requests: int = 5000,
    max_body_points: int = 200,
    active_tests: bool = False,
    allow_state_changing_methods: bool = False,
) -> Tuple[list[AttackSurface], Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return import_postman_data(
        data,
        target=target,
        scope=scope,
        allow_private=allow_private,
        max_requests=max_requests,
        max_body_points=max_body_points,
        active_tests=active_tests,
        allow_state_changing_methods=allow_state_changing_methods,
    )


def _surface_dict(surface: AttackSurface) -> dict[str, Any]:
    return {
        "url": surface.url,
        "method": surface.method,
        "params": sorted((surface.params or {}).keys()),
        "inputs": [
            {
                "name": item.name,
                "kind": item.kind,
                "path": item.path,
                "data_type": item.data_type,
            }
            for item in surface.inputs
        ],
        "source": surface.source,
        "meta": {
            "content_type": surface.meta.get("content_type", ""),
            "body_format": surface.meta.get("body_format", ""),
            "active_eligible": surface.meta.get("active_eligible", False),
            "folder_path": surface.meta.get("folder_path", []),
            "item_name": surface.meta.get("item_name", ""),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="web-vuln-postman",
        description=(
            "Import a Postman Collection v2.x JSON file into a sanitized, scoped "
            "attack-surface inventory without replaying collection requests."
        ),
    )
    parser.add_argument("collection", help="Postman Collection JSON file")
    parser.add_argument("--target", required=True, help="Authorized http(s) target used as import scope")
    parser.add_argument("--output", "-o", required=True, help="Output inventory JSON path")
    parser.add_argument("--max-requests", type=int, default=5000)
    parser.add_argument("--allow-private", action="store_true")
    args = parser.parse_args()

    try:
        surfaces, summary = import_postman_file(
            args.collection,
            target=args.target,
            allow_private=args.allow_private,
            max_requests=args.max_requests,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "format": "web-vuln-scanner-surface-inventory-v2",
                    "source": "postman",
                    "target": _target_base(args.target),
                    "summary": summary,
                    "surfaces": [_surface_dict(item) for item in surfaces],
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Postman import failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    print(f"Imported {len(surfaces)} sanitized Postman surface(s): {output}")


if __name__ == "__main__":
    main()
