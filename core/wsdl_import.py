from __future__ import annotations

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import AttackSurface, InputField
from .scope import ScopePolicy


WSDL11_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP11_WSDL_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP12_WSDL_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"
XSD_NAMESPACES = {
    "http://www.w3.org/2001/XMLSchema",
    "http://www.w3.org/1999/XMLSchema",
}


def _local(value: str) -> str:
    text = str(value or "")
    if text.startswith("{") and "}" in text:
        return text.split("}", 1)[1]
    return text.split(":", 1)[-1]


def _namespace(value: str) -> str:
    text = str(value or "")
    if text.startswith("{") and "}" in text:
        return text[1:].split("}", 1)[0]
    return ""


def _target_base(target: str) -> str:
    parsed = urlsplit(str(target or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target must not contain embedded credentials")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path or "/", "", ""))


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


def _safe_sample(xsd_type: str) -> Any:
    value_type = _local(xsd_type).lower()
    if value_type in {"byte", "short", "int", "integer", "long", "positiveinteger", "nonnegativeinteger"}:
        return 1
    if value_type in {"decimal", "double", "float"}:
        return 1.0
    if value_type == "boolean":
        return True
    return "TEST_VALUE"


def _iter_children_by_local(node: ET.Element, names: set[str]):
    for child in list(node):
        if _local(child.tag) in names:
            yield child


def _find_first_by_local(node: ET.Element, name: str) -> ET.Element | None:
    for child in node.iter():
        if _local(child.tag) == name:
            return child
    return None


def _schema_catalog(root: ET.Element):
    elements: dict[str, ET.Element] = {}
    complex_types: dict[str, ET.Element] = {}
    for node in root.iter():
        if _local(node.tag) != "schema" or _namespace(node.tag) not in XSD_NAMESPACES:
            continue
        for child in list(node):
            local = _local(child.tag)
            name = str(child.attrib.get("name", "") or "").strip()
            if not name:
                continue
            if local == "element":
                elements[name] = child
            elif local == "complexType":
                complex_types[name] = child
    return elements, complex_types


def _complex_for_element(element: ET.Element, complex_types: dict[str, ET.Element]) -> ET.Element | None:
    type_name = _local(element.attrib.get("type", ""))
    if type_name and type_name in complex_types:
        return complex_types[type_name]
    for child in list(element):
        if _local(child.tag) == "complexType":
            return child
    return None


def _xsd_inputs_for_element(
    element: ET.Element,
    *,
    complex_types: dict[str, ET.Element],
    base_path: str,
    max_depth: int,
    max_points: int,
) -> list[InputField]:
    points: list[InputField] = []
    visiting: set[str] = set()

    def walk_element(node: ET.Element, path: str, depth: int, required: bool) -> None:
        if len(points) >= max_points or depth > max_depth:
            return
        name = str(node.attrib.get("name", "") or "").strip()
        ref_name = _local(node.attrib.get("ref", ""))
        if not name:
            name = ref_name
        if not name:
            return
        current_path = f"{path}/{name}" if path else f"/{name}"
        node_type = str(node.attrib.get("type", "") or "")
        complex_node = _complex_for_element(node, complex_types)
        if complex_node is not None:
            type_key = _local(node_type) or name
            if type_key in visiting:
                return
            visiting.add(type_key)
            try:
                children = []
                for container in complex_node.iter():
                    if _local(container.tag) not in {"sequence", "all", "choice"}:
                        continue
                    children.extend(
                        child for child in list(container) if _local(child.tag) == "element"
                    )
                if children:
                    seen_ids = set()
                    for child in children:
                        marker = id(child)
                        if marker in seen_ids:
                            continue
                        seen_ids.add(marker)
                        min_occurs = str(child.attrib.get("minOccurs", "1") or "1")
                        walk_element(
                            child,
                            current_path,
                            depth + 1,
                            required=min_occurs != "0",
                        )
                    return
            finally:
                visiting.discard(type_key)

        points.append(
            InputField(
                name=name,
                value=_safe_sample(node_type),
                kind="body",
                path=current_path,
                data_type=_local(node_type) or "string",
                required=required,
            )
        )

    root_name = str(element.attrib.get("name", "") or "").strip() or "Request"
    root_complex = _complex_for_element(element, complex_types)
    if root_complex is None:
        return [
            InputField(
                name=root_name,
                value=_safe_sample(element.attrib.get("type", "")),
                kind="body",
                path=f"{base_path}/{root_name}",
                data_type=_local(element.attrib.get("type", "")) or "string",
                required=True,
            )
        ]

    for container in root_complex.iter():
        if _local(container.tag) not in {"sequence", "all", "choice"}:
            continue
        for child in list(container):
            if _local(child.tag) != "element":
                continue
            min_occurs = str(child.attrib.get("minOccurs", "1") or "1")
            walk_element(
                child,
                f"{base_path}/{root_name}",
                1,
                required=min_occurs != "0",
            )
        if points:
            break
    return points[:max_points]


def import_wsdl_data(
    raw: str | bytes,
    *,
    target: str,
    scope: ScopePolicy | None = None,
    allow_private: bool = False,
    max_operations: int = 1000,
    max_schema_depth: int = 8,
    max_insertion_points: int = 200,
) -> tuple[list[AttackSurface], dict[str, Any]]:
    if max_operations <= 0:
        raise ValueError("max_operations must be > 0")
    if max_schema_depth <= 0:
        raise ValueError("max_schema_depth must be > 0")
    if max_insertion_points <= 0:
        raise ValueError("max_insertion_points must be > 0")

    text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else str(raw or "")
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("DTD/ENTITY declarations are not allowed in WSDL input")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid WSDL XML: {exc}") from exc
    if _local(root.tag) != "definitions" or _namespace(root.tag) != WSDL11_NS:
        raise ValueError("Only WSDL 1.1 definitions are supported by this importer")

    scope = scope or _scope_for_target(target, allow_private=allow_private)
    elements, complex_types = _schema_catalog(root)

    messages: dict[str, list[dict[str, str]]] = {}
    port_types: dict[str, dict[str, str]] = {}
    bindings: dict[str, dict[str, Any]] = {}
    endpoints: list[dict[str, str]] = []

    for node in list(root):
        local = _local(node.tag)
        if local == "message":
            name = str(node.attrib.get("name", "") or "").strip()
            if not name:
                continue
            parts = []
            for part in _iter_children_by_local(node, {"part"}):
                parts.append(
                    {
                        "name": str(part.attrib.get("name", "") or ""),
                        "element": _local(part.attrib.get("element", "")),
                        "type": _local(part.attrib.get("type", "")),
                    }
                )
            messages[name] = parts
        elif local == "portType":
            name = str(node.attrib.get("name", "") or "").strip()
            if not name:
                continue
            operations = {}
            for operation in _iter_children_by_local(node, {"operation"}):
                op_name = str(operation.attrib.get("name", "") or "").strip()
                input_node = next(_iter_children_by_local(operation, {"input"}), None)
                if op_name:
                    operations[op_name] = _local(
                        input_node.attrib.get("message", "") if input_node is not None else ""
                    )
            port_types[name] = operations
        elif local == "binding":
            name = str(node.attrib.get("name", "") or "").strip()
            if not name:
                continue
            soap_version = "1.1"
            binding_style = ""
            binding_transport = ""
            for child in list(node):
                if _local(child.tag) == "binding" and _namespace(child.tag) in {SOAP11_WSDL_NS, SOAP12_WSDL_NS}:
                    soap_version = "1.2" if _namespace(child.tag) == SOAP12_WSDL_NS else "1.1"
                    binding_style = str(child.attrib.get("style", "") or "")
                    binding_transport = str(child.attrib.get("transport", "") or "")
            operations = {}
            for operation in _iter_children_by_local(node, {"operation"}):
                op_name = str(operation.attrib.get("name", "") or "").strip()
                soap_action = ""
                for child in list(operation):
                    if _local(child.tag) == "operation" and _namespace(child.tag) in {SOAP11_WSDL_NS, SOAP12_WSDL_NS}:
                        soap_action = str(child.attrib.get("soapAction", "") or "")
                        if _namespace(child.tag) == SOAP12_WSDL_NS:
                            soap_version = "1.2"
                if op_name:
                    operations[op_name] = soap_action
            bindings[name] = {
                "port_type": _local(node.attrib.get("type", "")),
                "operations": operations,
                "soap_version": soap_version,
                "style": binding_style,
                "transport": binding_transport,
            }
        elif local == "service":
            service_name = str(node.attrib.get("name", "") or "").strip()
            for port in _iter_children_by_local(node, {"port"}):
                binding_name = _local(port.attrib.get("binding", ""))
                address = ""
                soap_version = ""
                for child in list(port):
                    if _local(child.tag) == "address" and _namespace(child.tag) in {SOAP11_WSDL_NS, SOAP12_WSDL_NS}:
                        address = str(child.attrib.get("location", "") or "").strip()
                        soap_version = "1.2" if _namespace(child.tag) == SOAP12_WSDL_NS else "1.1"
                        break
                endpoints.append(
                    {
                        "service": service_name,
                        "port": str(port.attrib.get("name", "") or ""),
                        "binding": binding_name,
                        "address": address,
                        "soap_version": soap_version,
                    }
                )

    surfaces: list[AttackSurface] = []
    skipped = {"out_of_scope": 0, "missing_binding": 0, "truncated": 0}
    operations_seen = 0
    seen = set()

    for endpoint in endpoints or [{"service": "", "port": "", "binding": next(iter(bindings), ""), "address": "", "soap_version": ""}]:
        binding = bindings.get(endpoint.get("binding", ""))
        if not binding:
            skipped["missing_binding"] += 1
            continue
        address = endpoint.get("address") or _target_base(target)
        if not scope.is_allowed(address, resolve_dns=False):
            skipped["out_of_scope"] += 1
            continue
        port_operations = port_types.get(binding.get("port_type", ""), {})
        for operation_name, soap_action in (binding.get("operations") or {}).items():
            if operations_seen >= max_operations:
                skipped["truncated"] += 1
                break
            operations_seen += 1
            message_name = port_operations.get(operation_name, "")
            body_inputs: list[InputField] = []
            for part in messages.get(message_name, []):
                element_name = part.get("element", "")
                if element_name and element_name in elements:
                    body_inputs.extend(
                        _xsd_inputs_for_element(
                            elements[element_name],
                            complex_types=complex_types,
                            base_path=f"/Envelope/Body/{operation_name}",
                            max_depth=max_schema_depth,
                            max_points=max_insertion_points - len(body_inputs),
                        )
                    )
                elif part.get("name") and len(body_inputs) < max_insertion_points:
                    body_inputs.append(
                        InputField(
                            name=part["name"],
                            value=_safe_sample(part.get("type", "")),
                            kind="body",
                            path=f"/Envelope/Body/{operation_name}/{part['name']}",
                            data_type=part.get("type") or "string",
                        )
                    )
                if len(body_inputs) >= max_insertion_points:
                    break

            soap_version = endpoint.get("soap_version") or binding.get("soap_version") or "1.1"
            content_type = "application/soap+xml" if soap_version == "1.2" else "text/xml"
            surface = AttackSurface(
                url=address,
                method="POST",
                params={},
                inputs=body_inputs,
                source="wsdl",
                meta={
                    "wsdl": True,
                    "service": endpoint.get("service", ""),
                    "port": endpoint.get("port", ""),
                    "binding": endpoint.get("binding", ""),
                    "port_type": binding.get("port_type", ""),
                    "operation": operation_name,
                    "soap_action": soap_action,
                    "soap_version": soap_version,
                    "style": binding.get("style", ""),
                    "transport": binding.get("transport", ""),
                    "content_type": content_type,
                    "body_format": "xml",
                    "input_paths": [item.path or item.name for item in body_inputs],
                    "active_eligible": False,
                    "sanitized": True,
                    "replayed_requests": 0,
                },
            )
            if surface.id in seen:
                continue
            seen.add(surface.id)
            surfaces.append(surface)

    return surfaces, {
        "source": "wsdl",
        "version": "1.1",
        "services": len({item.get("service", "") for item in endpoints if item.get("service")}),
        "ports": len(endpoints),
        "bindings": len(bindings),
        "messages": len(messages),
        "schema_elements": len(elements),
        "operations_seen": operations_seen,
        "surfaces": len(surfaces),
        "input_points": sum(len(surface.inputs) for surface in surfaces),
        "active_eligible": 0,
        "replayed_requests": 0,
        "sanitized": True,
        "skipped": skipped,
    }


def import_wsdl_file(
    path: str | Path,
    *,
    target: str,
    scope: ScopePolicy | None = None,
    allow_private: bool = False,
    max_operations: int = 1000,
    max_schema_depth: int = 8,
    max_insertion_points: int = 200,
) -> tuple[list[AttackSurface], dict[str, Any]]:
    raw = Path(path).read_bytes()
    return import_wsdl_data(
        raw,
        target=target,
        scope=scope,
        allow_private=allow_private,
        max_operations=max_operations,
        max_schema_depth=max_schema_depth,
        max_insertion_points=max_insertion_points,
    )


def _surface_dict(surface: AttackSurface) -> dict[str, Any]:
    return {
        "url": surface.url,
        "method": surface.method,
        "inputs": [
            {
                "name": item.name,
                "kind": item.kind,
                "path": item.path,
                "data_type": item.data_type,
                "required": item.required,
            }
            for item in surface.inputs
        ],
        "source": surface.source,
        "meta": {
            "service": surface.meta.get("service", ""),
            "port": surface.meta.get("port", ""),
            "binding": surface.meta.get("binding", ""),
            "operation": surface.meta.get("operation", ""),
            "soap_action": surface.meta.get("soap_action", ""),
            "soap_version": surface.meta.get("soap_version", ""),
            "content_type": surface.meta.get("content_type", ""),
            "active_eligible": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="web-vuln-wsdl",
        description=(
            "Import a local WSDL 1.1 document into a sanitized, scoped SOAP "
            "attack-surface inventory without replaying service operations."
        ),
    )
    parser.add_argument("wsdl", help="Input WSDL 1.1 XML file")
    parser.add_argument("--target", required=True, help="Authorized http(s) target used as import scope")
    parser.add_argument("--output", "-o", required=True, help="Output inventory JSON path")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--max-operations", type=int, default=1000)
    args = parser.parse_args()

    try:
        surfaces, summary = import_wsdl_file(
            args.wsdl,
            target=args.target,
            allow_private=args.allow_private,
            max_operations=args.max_operations,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "format": "web-vuln-scanner-surface-inventory-v2",
                    "source": "wsdl",
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
        try:
            os.chmod(output, 0o600)
        except OSError:
            pass
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"WSDL import failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    print(f"Imported {len(surfaces)} sanitized WSDL surface(s): {output}")


if __name__ == "__main__":
    main()
