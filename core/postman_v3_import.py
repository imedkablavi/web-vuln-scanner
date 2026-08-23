from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .insertion_points import json_value_inputs
from .models import AttackSurface, InputField
from .postman_import import (
    _ALLOWED_METHODS,
    _query_inputs,
    _replace_variables,
    _request_url,
    _sanitize_input_values,
    _scope_for_target,
)
from .scope import ScopePolicy


_REQUEST_SUFFIXES = (".request.yaml", ".request.yml")
_DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_request_file(path: Path) -> bool:
    lowered = path.name.lower()
    return any(lowered.endswith(suffix) for suffix in _REQUEST_SUFFIXES)


def _request_files(root: Path, *, max_requests: int) -> tuple[list[Path], bool]:
    if max_requests <= 0:
        raise ValueError("max_requests must be > 0")
    if root.is_file():
        if not _is_request_file(root):
            raise ValueError("Postman v3 input file must end with .request.yaml or .request.yml")
        if root.is_symlink():
            raise ValueError("Postman v3 request symlinks are not imported")
        return [root], False
    if not root.is_dir():
        raise ValueError(f"Postman v3 collection path does not exist: {root}")

    resolved_root = root.resolve()
    discovered: list[Path] = []
    for candidate in root.rglob("*"):
        if len(discovered) >= max_requests:
            return discovered, True
        if candidate.is_symlink() or not candidate.is_file() or not _is_request_file(candidate):
            continue
        try:
            candidate.resolve().relative_to(resolved_root)
        except ValueError:
            continue
        discovered.append(candidate)
    discovered.sort(key=lambda item: item.as_posix().lower())
    return discovered[:max_requests], len(discovered) > max_requests


def _safe_yaml(path: Path, *, max_file_bytes: int) -> dict[str, Any]:
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be > 0")
    size = path.stat().st_size
    if size > max_file_bytes:
        raise ValueError(f"request file exceeds max_file_bytes ({size} > {max_file_bytes})")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("request YAML must contain a mapping")
    return data


def _json_body_inputs(
    body: Any,
    *,
    max_body_points: int,
) -> tuple[list[InputField], str, str, str]:
    """Parse only the v3 JSON body shape grounded in current Postman examples.

    Confirmed shape:
      body:
        type: json
        content: |-  # JSON text

    Unknown body types are inventory-visible but are not interpreted.
    """

    if not isinstance(body, dict):
        return [], "", "", ""
    body_type = str(body.get("type", "") or "").strip().lower()
    if body_type != "json":
        return [], "", body_type, "unsupported_body_type" if body_type else ""

    content = body.get("content")
    if not isinstance(content, str):
        return [], "application/json", "json", "json_content_not_string"
    try:
        payload = json.loads(content)
    except (TypeError, ValueError, json.JSONDecodeError):
        return [], "application/json", "json", "invalid_json_body"
    if not isinstance(payload, (dict, list)):
        return [], "application/json", "json", "json_body_not_object_or_array"

    points = json_value_inputs(payload, max_points=max_body_points)
    return _sanitize_input_values(points), "application/json", "json", ""


def _folder_path(root: Path, request_file: Path) -> list[str]:
    if root.is_file():
        return []
    try:
        parent = request_file.parent.resolve().relative_to(root.resolve())
    except ValueError:
        return []
    return [part for part in parent.parts if part not in {".", ""}]


def import_postman_v3_path(
    path: str | Path,
    *,
    target: str,
    scope: ScopePolicy | None = None,
    allow_private: bool = False,
    max_requests: int = 5000,
    max_body_points: int = 200,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> tuple[list[AttackSurface], dict[str, Any]]:
    """Import Postman Collection schema 3.0 request YAML as sanitized inventory.

    This adapter intentionally performs no request replay and marks every surface
    inventory-only. It interprets only schema fields grounded in current Postman
    documentation/examples: `$kind`, `name`, `url`, `method`, and JSON
    `body.type/body.content`.
    """

    if max_body_points <= 0:
        raise ValueError("max_body_points must be > 0")

    root = Path(path)
    files, truncated = _request_files(root, max_requests=max_requests)
    scope = scope or _scope_for_target(target, allow_private=allow_private)
    surfaces: list[AttackSurface] = []
    seen: set[str] = set()
    skipped = {
        "unsupported_kind": 0,
        "unsupported_method": 0,
        "missing_url": 0,
        "out_of_scope": 0,
        "invalid_yaml": 0,
        "duplicate": 0,
        "truncated": int(bool(truncated)),
    }
    body_diagnostics: dict[str, int] = {}
    files_seen = 0

    for request_file in files:
        files_seen += 1
        try:
            data = _safe_yaml(request_file, max_file_bytes=max_file_bytes)
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
            skipped["invalid_yaml"] += 1
            continue

        if str(data.get("$kind", "") or "").strip().lower() != "http-request":
            skipped["unsupported_kind"] += 1
            continue
        method = str(data.get("method", "GET") or "GET").upper()
        if method not in _ALLOWED_METHODS:
            skipped["unsupported_method"] += 1
            continue
        raw_url = str(data.get("url", "") or "").strip()
        if not raw_url:
            skipped["missing_url"] += 1
            continue

        rendered_url = _replace_variables(raw_url, target=target, variables={})
        try:
            url = _request_url(raw_url, target=target, variables={})
        except ValueError:
            skipped["missing_url"] += 1
            continue
        if not scope.is_allowed(url, resolve_dns=False):
            skipped["out_of_scope"] += 1
            continue

        params, query_inputs = _query_inputs({"url": raw_url}, rendered_url)
        body_inputs, content_type, body_format, body_diagnostic = _json_body_inputs(
            data.get("body"),
            max_body_points=max_body_points,
        )
        if body_diagnostic:
            body_diagnostics[body_diagnostic] = body_diagnostics.get(body_diagnostic, 0) + 1

        inputs = query_inputs + body_inputs
        surface = AttackSurface(
            url=url,
            method=method,
            params=params,
            inputs=inputs,
            source="postman-v3",
            meta={
                "postman": True,
                "postman_schema": "3.0.0",
                "item_name": str(data.get("name", "") or request_file.name),
                "folder_path": _folder_path(root, request_file),
                "request_file": request_file.name,
                "content_type": content_type,
                "body_format": body_format,
                "active_eligible": False,
                "sanitized": True,
                "original_values_retained": False,
                "replayed_requests": 0,
                "input_paths": [field.path or field.name for field in inputs],
            },
        )
        if surface.id in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(surface.id)
        surfaces.append(surface)

    return surfaces, {
        "source": "postman-v3",
        "schema": "3.0.0",
        "files_seen": files_seen,
        "surfaces": len(surfaces),
        "surfaces_with_inputs": sum(1 for item in surfaces if item.inputs or item.params),
        "input_points": sum(len(item.inputs) + len(item.params) for item in surfaces),
        "active_eligible": 0,
        "skipped": skipped,
        "body_diagnostics": body_diagnostics,
        "max_requests": max_requests,
        "max_body_points": max_body_points,
        "max_file_bytes": max_file_bytes,
        "sanitized": True,
        "replayed_requests": 0,
        "supported_fields": ["$kind", "name", "url", "method", "body.type=json", "body.content"],
    }
