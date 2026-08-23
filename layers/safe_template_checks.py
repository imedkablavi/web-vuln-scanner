from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from core.models import Finding
from core.scope import ScopePolicy


_ALLOWED_METHODS = {"GET", "HEAD"}
_ALLOWED_MATCHERS = {"status", "word", "header"}
_ALLOWED_PARTS = {"body", "header"}
_ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ALLOWED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
_MAX_MATCHERS_PER_TEMPLATE = 12
_MAX_VALUES_PER_MATCHER = 20
_MAX_MATCH_VALUE_LENGTH = 512


class TemplateValidationError(ValueError):
    pass


def _as_mapping(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise TemplateValidationError(f"{name} must be a mapping")
    return value


def _as_string_list(value: Any, name: str) -> List[str]:
    if not isinstance(value, list) or not value:
        raise TemplateValidationError(f"{name} must be a non-empty list")
    result = []
    for item in value:
        if not isinstance(item, (str, int)):
            raise TemplateValidationError(f"{name} values must be strings or integers")
        text = str(item)
        if len(text) > _MAX_MATCH_VALUE_LENGTH:
            raise TemplateValidationError(
                f"{name} contains a value longer than {_MAX_MATCH_VALUE_LENGTH} characters"
            )
        result.append(text)
    if len(result) > _MAX_VALUES_PER_MATCHER:
        raise TemplateValidationError(
            f"{name} may contain at most {_MAX_VALUES_PER_MATCHER} values"
        )
    return result


def validate_safe_template(raw: Dict[str, Any]) -> Dict[str, Any]:
    template = _as_mapping(raw, "template")
    template_id = str(template.get("id", "") or "").strip()
    if not template_id or len(template_id) > 120:
        raise TemplateValidationError("template.id must be 1-120 characters")
    if not all(ch.isalnum() or ch in {"-", "_", "."} for ch in template_id):
        raise TemplateValidationError(
            "template.id may only contain letters, numbers, dot, dash, and underscore"
        )

    info = _as_mapping(template.get("info", {}), "template.info")
    name = str(info.get("name", "") or "").strip()
    if not name:
        raise TemplateValidationError("template.info.name is required")
    severity = str(info.get("severity", "INFO") or "INFO").upper()
    confidence = str(info.get("confidence", "HIGH") or "HIGH").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise TemplateValidationError(f"unsupported template severity: {severity}")
    if confidence not in _ALLOWED_CONFIDENCE:
        raise TemplateValidationError(f"unsupported template confidence: {confidence}")
    remediation = str(info.get("remediation", "") or "").strip()
    if not remediation:
        raise TemplateValidationError("template.info.remediation is required")

    request = _as_mapping(template.get("request", {}), "template.request")
    method = str(request.get("method", "GET") or "GET").upper()
    if method not in _ALLOWED_METHODS:
        raise TemplateValidationError("safe templates only support GET or HEAD")
    path = str(request.get("path", "") or "").strip()
    if not path.startswith("/") or path.startswith("//"):
        raise TemplateValidationError(
            "template.request.path must be an absolute same-origin path beginning with one slash"
        )
    parsed_path = urlsplit(path)
    if parsed_path.scheme or parsed_path.netloc or parsed_path.username is not None:
        raise TemplateValidationError("template.request.path must not contain an origin or userinfo")
    if parsed_path.fragment:
        raise TemplateValidationError("template.request.path must not contain a fragment")
    if "{{" in path or "}}" in path:
        raise TemplateValidationError("template variables and DSL expressions are not supported")

    matchers = template.get("matchers", [])
    if not isinstance(matchers, list) or not matchers:
        raise TemplateValidationError("template.matchers must be a non-empty list")
    if len(matchers) > _MAX_MATCHERS_PER_TEMPLATE:
        raise TemplateValidationError(
            f"template.matchers may contain at most {_MAX_MATCHERS_PER_TEMPLATE} entries"
        )

    normalized_matchers = []
    for index, raw_matcher in enumerate(matchers):
        matcher = _as_mapping(raw_matcher, f"template.matchers[{index}]")
        kind = str(matcher.get("type", "") or "").strip().lower()
        if kind not in _ALLOWED_MATCHERS:
            raise TemplateValidationError(
                f"template.matchers[{index}].type must be status, word, or header"
            )
        condition = str(matcher.get("condition", "any") or "any").lower()
        if condition not in {"any", "all"}:
            raise TemplateValidationError(
                f"template.matchers[{index}].condition must be any or all"
            )
        negative = matcher.get("negative", False)
        if not isinstance(negative, bool):
            raise TemplateValidationError(
                f"template.matchers[{index}].negative must be boolean"
            )

        if kind == "status":
            values = _as_string_list(
                matcher.get("values", []), f"template.matchers[{index}].values"
            )
            try:
                statuses = [int(value) for value in values]
            except ValueError as exc:
                raise TemplateValidationError("status matcher values must be integers") from exc
            if any(value < 100 or value > 599 for value in statuses):
                raise TemplateValidationError("status matcher values must be 100-599")
            normalized_matchers.append(
                {
                    "type": kind,
                    "values": statuses,
                    "condition": condition,
                    "negative": negative,
                }
            )
            continue

        if kind == "word":
            part = str(matcher.get("part", "body") or "body").lower()
            if part not in _ALLOWED_PARTS:
                raise TemplateValidationError("word matcher part must be body or header")
            normalized_matchers.append(
                {
                    "type": kind,
                    "part": part,
                    "values": _as_string_list(
                        matcher.get("values", []),
                        f"template.matchers[{index}].values",
                    ),
                    "condition": condition,
                    "negative": negative,
                    "case_sensitive": bool(matcher.get("case_sensitive", False)),
                }
            )
            continue

        header_name = str(matcher.get("name", "") or "").strip()
        if not header_name or any(ch in header_name for ch in "\r\n:"):
            raise TemplateValidationError("header matcher requires a safe header name")
        normalized_matchers.append(
            {
                "type": kind,
                "name": header_name,
                "values": _as_string_list(
                    matcher.get("values", []), f"template.matchers[{index}].values"
                ),
                "condition": condition,
                "negative": negative,
                "case_sensitive": bool(matcher.get("case_sensitive", False)),
            }
        )

    matchers_condition = str(template.get("matchers_condition", "all") or "all").lower()
    if matchers_condition not in {"all", "any"}:
        raise TemplateValidationError("template.matchers_condition must be all or any")

    return {
        "id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "confidence": confidence,
            "category": str(info.get("category", "safe-template") or "safe-template").strip().lower(),
            "remediation": remediation,
            "description": str(info.get("description", "") or "").strip(),
        },
        "request": {"method": method, "path": path},
        "matchers_condition": matchers_condition,
        "matchers": normalized_matchers,
    }


def _load_yaml_document(text: str, source: str) -> Dict[str, Any]:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise TemplateValidationError(f"invalid YAML in {source}: {exc}") from exc
    return validate_safe_template(raw)


def _bounded_body(response: Any, max_body_bytes: int) -> str:
    text = str(getattr(response, "text", "") or "")
    data = text.encode("utf-8", errors="replace")[:max_body_bytes]
    return data.decode("utf-8", errors="replace")


def _header_blob(headers: Dict[str, Any]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in headers.items())


def _string_matches(haystack: str, values: Iterable[str], *, condition: str, case_sensitive: bool) -> bool:
    source = haystack if case_sensitive else haystack.lower()
    needles = list(values)
    if not case_sensitive:
        needles = [value.lower() for value in needles]
    results = [needle in source for needle in needles]
    return all(results) if condition == "all" else any(results)


def _matcher_result(matcher: Dict[str, Any], response: Any, body: str, headers: Dict[str, Any]) -> bool:
    kind = matcher["type"]
    if kind == "status":
        matched = int(getattr(response, "status_code", 0) or 0) in matcher["values"]
    elif kind == "word":
        haystack = body if matcher["part"] == "body" else _header_blob(headers)
        matched = _string_matches(
            haystack,
            matcher["values"],
            condition=matcher["condition"],
            case_sensitive=matcher["case_sensitive"],
        )
    else:
        selected = ""
        target_name = matcher["name"].lower()
        for key, value in headers.items():
            if str(key).lower() == target_name:
                selected = str(value)
                break
        matched = _string_matches(
            selected,
            matcher["values"],
            condition=matcher["condition"],
            case_sensitive=matcher["case_sensitive"],
        )
    return not matched if matcher.get("negative", False) else matched


def _template_matches(template: Dict[str, Any], response: Any, body: str) -> bool:
    headers = dict(getattr(response, "headers", {}) or {})
    results = [
        _matcher_result(matcher, response, body, headers)
        for matcher in template["matchers"]
    ]
    return all(results) if template["matchers_condition"] == "all" else any(results)


class SafeTemplateScanner:
    """Bounded same-origin GET/HEAD template checks without DSL or raw HTTP."""

    def __init__(self, requester: Any, config: Dict[str, Any]):
        self.requester = requester
        self.config = config
        self.layer_config = (
            config.get("active_checks", {}).get("templates", {}) or {}
        )
        self.enabled = bool(self.layer_config.get("enabled", False))
        self.include_builtin = bool(self.layer_config.get("include_builtin", True))
        self.directory = str(self.layer_config.get("directory", "") or "").strip()
        self.files = [
            str(item) for item in self.layer_config.get("files", []) or [] if str(item).strip()
        ]
        self.max_templates = max(1, int(self.layer_config.get("max_templates", 25) or 25))
        self.max_requests = max(1, int(self.layer_config.get("max_requests", 25) or 25))
        self.max_body_bytes = max(
            1024, int(self.layer_config.get("max_body_bytes", 131072) or 131072)
        )
        self.scope = getattr(requester, "scope_policy", None) or ScopePolicy(config)
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []

    def _template_sources(self) -> List[Tuple[str, str]]:
        sources: List[Tuple[str, str]] = []
        if self.include_builtin:
            root = resources.files("config").joinpath("safe_templates")
            if root.is_dir():
                for item in sorted(root.iterdir(), key=lambda value: value.name):
                    if item.is_file() and item.name.lower().endswith((".yaml", ".yml")):
                        sources.append((f"builtin:{item.name}", item.read_text(encoding="utf-8")))

        custom_paths: List[Path] = []
        if self.directory:
            directory = Path(self.directory)
            if directory.is_dir():
                custom_paths.extend(
                    sorted(
                        (
                            item
                            for item in directory.iterdir()
                            if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}
                        ),
                        key=lambda value: value.name,
                    )
                )
            else:
                self.errors.append(
                    {"kind": "template_directory", "path": self.directory, "error": "not_found"}
                )
        custom_paths.extend(Path(item) for item in self.files)

        seen = set()
        for path in custom_paths:
            try:
                resolved = path.expanduser().resolve()
            except OSError:
                resolved = path
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            try:
                sources.append((key, resolved.read_text(encoding="utf-8")))
            except OSError as exc:
                self.errors.append(
                    {"kind": "template_file", "path": key, "error": str(exc)}
                )
        return sources

    def _load_templates(self) -> List[Tuple[str, Dict[str, Any]]]:
        loaded: List[Tuple[str, Dict[str, Any]]] = []
        ids = set()
        for source, text in self._template_sources():
            if len(loaded) >= self.max_templates:
                self.skipped.append(
                    f"Stopped after {self.max_templates} safe templates; raise active_checks.templates.max_templates to load more."
                )
                break
            try:
                template = _load_yaml_document(text, source)
            except TemplateValidationError as exc:
                self.errors.append(
                    {"kind": "template_validation", "source": source, "error": str(exc)}
                )
                continue
            if template["id"] in ids:
                self.errors.append(
                    {
                        "kind": "template_validation",
                        "source": source,
                        "error": f"duplicate template id: {template['id']}",
                    }
                )
                continue
            ids.add(template["id"])
            loaded.append((source, template))
        return loaded

    @staticmethod
    def _origin(target: str) -> str:
        parsed = urlsplit(str(target or ""))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("safe template target must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("safe template target must not contain URL credentials")
        return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))

    def scan(self, target: str) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta(loaded=0, executed=0, matched=0)

        try:
            origin = self._origin(target)
        except ValueError as exc:
            self.errors.append({"kind": "template_target", "error": str(exc)})
            return [], self._meta(loaded=0, executed=0, matched=0)

        templates = self._load_templates()
        findings: List[Finding] = []
        executed = 0
        for source, template in templates:
            if executed >= self.max_requests:
                self.skipped.append(
                    f"Stopped after {self.max_requests} safe-template requests; raise active_checks.templates.max_requests to execute more."
                )
                break
            request = template["request"]
            url = urljoin(origin, request["path"])
            if not self.scope.is_allowed(url, resolve_dns=False):
                self.errors.append(
                    {
                        "kind": "template_scope",
                        "template": template["id"],
                        "source": source,
                        "url": url,
                        "error": "blocked_by_scope",
                    }
                )
                continue

            try:
                response = self.requester.send(
                    request["method"],
                    url,
                    allow_redirects=False,
                )
                executed += 1
            except Exception as exc:
                self.errors.append(
                    {
                        "kind": "template_request",
                        "template": template["id"],
                        "source": source,
                        "url": url,
                        "error": str(exc),
                    }
                )
                continue

            body = _bounded_body(response, self.max_body_bytes)
            if not _template_matches(template, response, body):
                continue
            info = template["info"]
            findings.append(
                Finding(
                    plugin="safe_template",
                    type=template["id"],
                    title=info["name"],
                    category=info["category"],
                    severity=info["severity"],
                    confidence=info["confidence"],
                    surface_id=f"safe-template:{template['id']}:{url}",
                    url=url,
                    evidence={
                        "template_id": template["id"],
                        "status": int(getattr(response, "status_code", 0) or 0),
                        "matcher_types": [item["type"] for item in template["matchers"]],
                        "body_bytes_inspected": len(body.encode("utf-8", errors="replace")),
                    },
                    remediation=info["remediation"],
                    reproduction={
                        "method": request["method"],
                        "url": url,
                        "template_id": template["id"],
                    },
                    verification_status="detected",
                    scanner_mode="safe-active",
                    reproducible=True,
                    target={"source": "safe-template", "template_id": template["id"]},
                    notes=(
                        [info["description"]]
                        if info.get("description")
                        else []
                    ),
                )
            )

        return findings, self._meta(
            loaded=len(templates),
            executed=executed,
            matched=len(findings),
        )

    def _meta(self, *, loaded: int, executed: int, matched: int) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "include_builtin": self.include_builtin,
            "loaded_templates": loaded,
            "executed_requests": executed,
            "matched_templates": matched,
            "max_templates": self.max_templates,
            "max_requests": self.max_requests,
            "max_body_bytes": self.max_body_bytes,
            "supported_methods": sorted(_ALLOWED_METHODS),
            "supported_matchers": sorted(_ALLOWED_MATCHERS),
            "errors": self.errors,
            "skipped": self.skipped,
            "raw_http": False,
            "dsl": False,
            "redirects_followed": False,
        }
