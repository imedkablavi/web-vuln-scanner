from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .models import AttackSurface, InputField
from .scope import ScopePolicy


_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_SAFE_SEED_METHODS = {"GET", "HEAD"}
_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}


def _safe_netloc(parsed) -> str:
    host = parsed.hostname or ""
    if not host:
        return ""
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    return f"{rendered_host}:{port}" if port is not None else rendered_host


def _sanitized_url(value: str, *, keep_query: bool = True) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be an absolute http(s) URL")
    return urlunsplit(
        (
            parsed.scheme,
            _safe_netloc(parsed),
            parsed.path or "/",
            parsed.query if keep_query else "",
            "",
        )
    )


def _scope_config(target: str, *, allow_private: bool = False) -> Dict[str, Any]:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target must not contain embedded URL credentials")
    safe_target = _sanitized_url(target, keep_query=False)
    safe_netloc = urlsplit(safe_target).netloc
    return {
        "target": safe_target,
        "scope": {
            "allowlist": [safe_netloc],
            "include_domains": [safe_netloc],
            "exclude_paths": [],
            "allow_private": bool(allow_private),
            "resolve_dns": False,
        },
        "crawler": {"max_url_length": 4096},
        "concurrency": {"global_timeout_seconds": 60},
    }


def _base_url(value: str) -> str:
    return _sanitized_url(value, keep_query=False)


def _header_names(headers: Iterable[Dict[str, Any]]) -> List[str]:
    names = []
    for header in headers or []:
        name = str((header or {}).get("name", "")).strip()
        if not name or name.lower() in _SENSITIVE_HEADER_NAMES:
            continue
        if name.lower() in {"content-type", "accept", "origin", "referer", "user-agent"}:
            names.append(name)
    return sorted(set(names), key=str.lower)


def _body_fields(post_data: Dict[str, Any]) -> List[str]:
    names = []
    for item in post_data.get("params", []) or []:
        name = str((item or {}).get("name", "")).strip()
        if name:
            names.append(name)

    mime = str(post_data.get("mimeType", "") or "").lower()
    text = str(post_data.get("text", "") or "")
    if text and "json" in mime:
        try:
            payload = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            names.extend(str(key) for key in payload.keys())
    return sorted(set(names))


def _surface_from_request(request: Dict[str, Any], scope: ScopePolicy) -> Dict[str, Any] | None:
    raw_url = str(request.get("url", "") or "").strip()
    method = str(request.get("method", "GET") or "GET").upper()
    if method not in _ALLOWED_METHODS or not raw_url:
        return None

    try:
        scope_url = _sanitized_url(raw_url, keep_query=True)
    except ValueError:
        return None
    if not scope.is_allowed(scope_url, resolve_dns=False):
        return None

    parsed = urlsplit(raw_url)
    query_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)})
    post_data = request.get("postData") or {}
    body_names = _body_fields(post_data) if isinstance(post_data, dict) else []
    header_names = _header_names(request.get("headers") or [])

    inputs = []
    inputs.extend({"name": name, "kind": "query", "value": ""} for name in query_names)
    inputs.extend({"name": name, "kind": "body", "value": ""} for name in body_names)

    return {
        "url": _base_url(raw_url),
        "method": method,
        "params": {name: "" for name in query_names},
        "inputs": inputs,
        "source": "har-import",
        "meta": {
            "content_type": str(post_data.get("mimeType", "") or "") if isinstance(post_data, dict) else "",
            "observed_header_names": header_names,
            "sanitized": True,
        },
    }


def _fingerprint(surface: Dict[str, Any]) -> tuple[Any, ...]:
    return (
        surface.get("method", ""),
        surface.get("url", ""),
        tuple(sorted((surface.get("params") or {}).keys())),
        tuple(sorted((item.get("kind"), item.get("name")) for item in surface.get("inputs", []) or [])),
    )


def _har_entries(data: Dict[str, Any], max_entries: int) -> Tuple[List[Dict[str, Any]], bool]:
    if not isinstance(data, dict):
        raise ValueError("HAR document must be a JSON object")
    log = data.get("log")
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise ValueError("HAR document is missing log.entries")
    if max_entries <= 0:
        raise ValueError("max_entries must be > 0")
    all_entries = log.get("entries", [])
    return all_entries[:max_entries], len(all_entries) > max_entries


def import_har_data(
    data: Dict[str, Any],
    *,
    target: str,
    allow_private: bool = False,
    max_entries: int = 5000,
) -> Dict[str, Any]:
    entries, truncated = _har_entries(data, max_entries)

    scope_config = _scope_config(target, allow_private=allow_private)
    scope = ScopePolicy(scope_config)
    surfaces: List[Dict[str, Any]] = []
    seen = set()
    skipped = {"out_of_scope": 0, "unsupported": 0, "duplicate": 0}

    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            skipped["unsupported"] += 1
            continue
        request = entry["request"]
        raw_url = str(request.get("url", "") or "").strip()
        method = str(request.get("method", "GET") or "GET").upper()
        if method not in _ALLOWED_METHODS or not raw_url:
            skipped["unsupported"] += 1
            continue
        try:
            scope_url = _sanitized_url(raw_url, keep_query=True)
        except ValueError:
            skipped["unsupported"] += 1
            continue
        if not scope.is_allowed(scope_url, resolve_dns=False):
            skipped["out_of_scope"] += 1
            continue
        surface = _surface_from_request(request, scope)
        if surface is None:
            skipped["unsupported"] += 1
            continue
        key = _fingerprint(surface)
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)
        surfaces.append(surface)

    return {
        "format": "web-vuln-scanner-surface-inventory-v1",
        "target": scope_config["target"],
        "source": "har",
        "sanitized": True,
        "summary": {
            "entries_seen": len(entries),
            "surfaces": len(surfaces),
            "skipped": skipped,
            "truncated": truncated,
            "max_entries": max_entries,
        },
        "surfaces": surfaces,
    }


def import_har_file(
    path: str | Path,
    *,
    target: str,
    allow_private: bool = False,
    max_entries: int = 5000,
) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return import_har_data(
        data,
        target=target,
        allow_private=allow_private,
        max_entries=max_entries,
    )


def har_seed_data(
    data: Dict[str, Any],
    *,
    scope: ScopePolicy,
    max_entries: int = 5000,
    active_tests: bool = False,
) -> Tuple[List[AttackSurface], Dict[str, Any]]:
    """Build safe scanner seeds from HAR without replaying captured requests.

    Only GET and HEAD entries become seeds. Parameter *names* are retained while
    values are replaced with empty strings. Authorization/cookie material is not
    copied. Active plugin testing stays disabled per surface unless explicitly
    enabled, and HEAD entries remain passive-only even when active_tests=True.
    """

    entries, truncated = _har_entries(data, max_entries)
    surfaces: List[AttackSurface] = []
    seen = set()
    skipped = {
        "out_of_scope": 0,
        "unsupported": 0,
        "non_safe_method": 0,
        "duplicate": 0,
    }

    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            skipped["unsupported"] += 1
            continue
        request = entry["request"]
        method = str(request.get("method", "GET") or "GET").upper()
        if method not in _ALLOWED_METHODS:
            skipped["unsupported"] += 1
            continue
        if method not in _SAFE_SEED_METHODS:
            skipped["non_safe_method"] += 1
            continue
        raw_url = str(request.get("url", "") or "").strip()
        try:
            scope_url = _sanitized_url(raw_url, keep_query=True)
        except ValueError:
            skipped["unsupported"] += 1
            continue
        if not scope.is_allowed(scope_url, resolve_dns=False):
            skipped["out_of_scope"] += 1
            continue
        sanitized = _surface_from_request(request, scope)
        if sanitized is None:
            skipped["unsupported"] += 1
            continue

        query_inputs = [
            InputField(name=item["name"], value="", kind="query")
            for item in sanitized.get("inputs", [])
            if item.get("kind") == "query"
        ]
        surface = AttackSurface(
            url=str(sanitized["url"]),
            method=method,
            params={str(name): "" for name in (sanitized.get("params") or {})},
            inputs=query_inputs,
            source="har-seed",
            meta={
                "sanitized": True,
                "active_eligible": bool(active_tests and method == "GET"),
                "har_seed": True,
                "observed_header_names": sanitized.get("meta", {}).get(
                    "observed_header_names", []
                ),
            },
        )
        key = surface.id
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)
        surfaces.append(surface)

    return surfaces, {
        "entries_seen": len(entries),
        "surfaces": len(surfaces),
        "active_eligible": sum(
            1 for item in surfaces if item.meta.get("active_eligible", False)
        ),
        "skipped": skipped,
        "truncated": truncated,
        "max_entries": max_entries,
        "replayed_requests": 0,
        "sanitized": True,
    }


def load_har_seed_file(
    path: str | Path,
    *,
    scope: ScopePolicy,
    max_entries: int = 5000,
    active_tests: bool = False,
) -> Tuple[List[AttackSurface], Dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return har_seed_data(
        data,
        scope=scope,
        max_entries=max_entries,
        active_tests=active_tests,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="web-vuln-har",
        description="Convert a HAR file into a sanitized, scoped attack-surface inventory without replaying requests.",
    )
    parser.add_argument("har", help="Input HAR JSON file")
    parser.add_argument("--target", required=True, help="Authorized http(s) target used as the import scope")
    parser.add_argument("--output", "-o", required=True, help="Output inventory JSON path")
    parser.add_argument("--max-entries", type=int, default=5000, help="Maximum HAR requests to inspect (default: 5000)")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private/loopback targets when the supplied target itself is an authorized private asset",
    )
    args = parser.parse_args()

    try:
        inventory = import_har_file(
            args.har,
            target=args.target,
            allow_private=args.allow_private,
            max_entries=args.max_entries,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"HAR import failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    print(
        f"Imported {inventory['summary']['surfaces']} sanitized surface(s) "
        f"from {inventory['summary']['entries_seen']} HAR request(s): {output}"
    )


if __name__ == "__main__":
    main()