from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl
from xml.etree import ElementTree

from .models import InputField


_JSON_TYPES = {
    str: "string",
    bool: "boolean",
    int: "integer",
    float: "number",
    type(None): "null",
}


def escape_json_pointer_token(value: str) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def unescape_json_pointer_token(value: str) -> str:
    return str(value).replace("~1", "/").replace("~0", "~")


def pointer_join(pointer: str, token: str | int) -> str:
    encoded = escape_json_pointer_token(str(token))
    return f"{pointer}/{encoded}" if pointer else f"/{encoded}"


def _leaf_name(pointer: str, fallback: str = "body") -> str:
    if not pointer:
        return fallback
    return unescape_json_pointer_token(pointer.rsplit("/", 1)[-1]) or fallback


def _value_type(value: Any) -> str:
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return _JSON_TYPES.get(type(value), type(value).__name__)


def json_value_inputs(
    value: Any,
    *,
    kind: str = "body",
    max_depth: int = 8,
    max_points: int = 200,
) -> list[InputField]:
    """Flatten a JSON-compatible value into leaf insertion points.

    Paths use RFC 6901-style JSON Pointers. Values stay in memory for request
    reconstruction, but reporting/site-map code is expected to persist only
    names, paths, and types.
    """

    points: list[InputField] = []

    def walk(current: Any, pointer: str, depth: int) -> None:
        if len(points) >= max_points:
            return
        if depth > max_depth:
            return
        if isinstance(current, dict):
            if not current:
                return
            for key, item in current.items():
                walk(item, pointer_join(pointer, str(key)), depth + 1)
                if len(points) >= max_points:
                    break
            return
        if isinstance(current, list):
            if not current:
                return
            # A concrete sample can contain heterogeneous array entries. Retain
            # actual indexes because they are needed to reconstruct that sample.
            for index, item in enumerate(current):
                walk(item, pointer_join(pointer, index), depth + 1)
                if len(points) >= max_points:
                    break
            return
        points.append(
            InputField(
                name=_leaf_name(pointer),
                value=current,
                kind=kind,
                path=pointer,
                data_type=_value_type(current),
            )
        )

    walk(value, "", 0)
    return points


def _schema_sample(schema: dict[str, Any]) -> Any:
    if "example" in schema:
        return schema.get("example")
    if "default" in schema:
        return schema.get("default")
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    value_type = str(schema.get("type", "") or "")
    if value_type == "integer":
        return 1
    if value_type == "number":
        return 1.0
    if value_type == "boolean":
        return True
    if value_type == "array":
        return []
    if value_type == "object":
        return {}
    return "TEST_VALUE"


def schema_inputs(
    schema: dict[str, Any] | None,
    *,
    resolve_ref: Callable[[str], dict[str, Any] | None] | None = None,
    kind: str = "body",
    max_depth: int = 8,
    max_points: int = 200,
) -> list[InputField]:
    """Flatten an OpenAPI/JSON-schema-like document into insertion points."""

    points: list[InputField] = []
    resolving: set[str] = set()

    def resolved(current: Any) -> dict[str, Any]:
        if not isinstance(current, dict):
            return {}
        ref = current.get("$ref")
        if isinstance(ref, str) and resolve_ref and ref not in resolving:
            resolving.add(ref)
            try:
                target = resolve_ref(ref)
                if isinstance(target, dict):
                    merged = dict(target)
                    merged.update({k: v for k, v in current.items() if k != "$ref"})
                    return merged
            finally:
                resolving.discard(ref)
        return current

    def walk(current: Any, pointer: str, depth: int, is_required: bool = False) -> None:
        if len(points) >= max_points or depth > max_depth:
            return
        current = resolved(current)
        if not current:
            return

        all_of = current.get("allOf")
        if isinstance(all_of, list):
            for part in all_of:
                walk(part, pointer, depth + 1, is_required)
                if len(points) >= max_points:
                    return
            return

        properties = current.get("properties")
        if isinstance(properties, dict):
            required_names = set(current.get("required", []) or [])
            for name, child in properties.items():
                walk(
                    child,
                    pointer_join(pointer, str(name)),
                    depth + 1,
                    str(name) in required_names,
                )
                if len(points) >= max_points:
                    return
            return

        value_type = str(current.get("type", "") or "")
        if value_type == "array" or isinstance(current.get("items"), dict):
            items = current.get("items")
            if isinstance(items, dict):
                # Index zero is a structural placeholder for an array item. It
                # makes the path directly usable for request materialization.
                walk(items, pointer_join(pointer, 0), depth + 1, is_required)
            return

        points.append(
            InputField(
                name=_leaf_name(pointer),
                value=_schema_sample(current),
                kind=kind,
                path=pointer,
                data_type=value_type or "string",
                required=bool(is_required),
            )
        )

    walk(schema or {}, "", 0)
    return points


def _xml_local_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1].split(":", 1)[-1]


def xml_value_inputs(
    raw: str,
    *,
    kind: str = "body",
    max_depth: int = 8,
    max_points: int = 200,
) -> list[InputField]:
    """Extract XML element-text insertion points without resolving entities."""

    text = str(raw or "")
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return []
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []

    points: list[InputField] = []

    def walk(element: ElementTree.Element, path: str, depth: int) -> None:
        if len(points) >= max_points or depth > max_depth:
            return
        name = _xml_local_name(element.tag)
        current_path = f"{path}/{name}" if path else f"/{name}"
        children = list(element)
        if children:
            for child in children:
                walk(child, current_path, depth + 1)
            return
        points.append(
            InputField(
                name=name,
                value=element.text or "",
                kind=kind,
                path=current_path,
                data_type="xml-text",
            )
        )

    walk(root, "", 0)
    return points


def body_inputs_from_raw(
    raw: str,
    *,
    content_type: str = "",
    mode: str = "",
    max_points: int = 200,
) -> list[InputField]:
    lowered = str(content_type or "").lower()
    normalized_mode = str(mode or "").lower()
    text = str(raw or "")

    if "json" in lowered or normalized_mode in {"json", "graphql"}:
        try:
            value = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        return json_value_inputs(value, max_points=max_points)

    if "xml" in lowered or normalized_mode == "xml":
        return xml_value_inputs(text, max_points=max_points)

    if "application/x-www-form-urlencoded" in lowered or normalized_mode == "urlencoded":
        return [
            InputField(
                name=name,
                value=value,
                kind="body",
                path=name,
                data_type="string",
            )
            for name, value in parse_qsl(text, keep_blank_values=True)[:max_points]
            if name
        ]
    return []


def _pointer_tokens(pointer: str) -> list[str]:
    if not pointer:
        return []
    if not pointer.startswith("/"):
        raise ValueError("JSON insertion path must be an RFC 6901-style pointer")
    return [unescape_json_pointer_token(item) for item in pointer.split("/")[1:]]


def set_json_pointer(document: Any, pointer: str, value: Any) -> Any:
    """Return a deep-copied JSON value with one pointer replaced/created."""

    tokens = _pointer_tokens(pointer)
    if not tokens:
        return deepcopy(value)
    result = deepcopy(document)
    if result is None:
        result = [] if tokens[0].isdigit() else {}

    cursor = result
    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        if isinstance(cursor, list):
            if not token.isdigit():
                raise ValueError(f"Array insertion token is not numeric: {token}")
            position = int(token)
            while len(cursor) <= position:
                cursor.append(None)
            if not isinstance(cursor[position], (dict, list)):
                cursor[position] = [] if next_token.isdigit() else {}
            cursor = cursor[position]
            continue
        if not isinstance(cursor, dict):
            raise ValueError("Cannot descend through a scalar JSON value")
        if token not in cursor or not isinstance(cursor[token], (dict, list)):
            cursor[token] = [] if next_token.isdigit() else {}
        cursor = cursor[token]

    final = tokens[-1]
    if isinstance(cursor, list):
        if not final.isdigit():
            raise ValueError(f"Array insertion token is not numeric: {final}")
        position = int(final)
        while len(cursor) <= position:
            cursor.append(None)
        cursor[position] = deepcopy(value)
    elif isinstance(cursor, dict):
        cursor[final] = deepcopy(value)
    else:
        raise ValueError("Cannot set a value below a scalar JSON value")
    return result


def json_document_from_inputs(inputs: Iterable[InputField]) -> Any:
    document: Any = {}
    for field in inputs or []:
        if str(getattr(field, "kind", "") or "").lower() != "body":
            continue
        pointer = str(getattr(field, "path", "") or "")
        if not pointer.startswith("/"):
            if field.name:
                document[str(field.name)] = field.value
            continue
        document = set_json_pointer(document, pointer, field.value)
    return document


def mutate_json_inputs(
    inputs: Iterable[InputField],
    *,
    name: str,
    path: str = "",
    payload: Any,
) -> Any:
    body_inputs = [
        field
        for field in inputs or []
        if str(getattr(field, "kind", "") or "").lower() == "body"
    ]
    document = json_document_from_inputs(body_inputs)
    selected_path = str(path or "")
    if not selected_path:
        matches = [field for field in body_inputs if field.name == name]
        if len(matches) > 1:
            raise ValueError(
                f"Body input '{name}' is ambiguous; a canonical insertion path is required"
            )
        if matches:
            selected_path = str(getattr(matches[0], "path", "") or "")
    if selected_path.startswith("/"):
        return set_json_pointer(document, selected_path, payload)
    result = deepcopy(document)
    if not isinstance(result, dict):
        result = {}
    result[name] = payload
    return result
