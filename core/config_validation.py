from __future__ import annotations

from typing import Any, Dict, List


_SCANNER_KEYS = {
    "target",
    "profile",
    "scope",
    "crawler",
    "concurrency",
    "plugin_contract",
    "browser_enabled",
    "crawler_enabled",
    "debug",
    "browser",
    "auth",
    "auth_verification",
    "rbac_matrix",
    "rbac_matrix_file",
    "workflows",
    "plugins",
    "output",
    "api",
    "passive_checks",
    "active_checks",
    "verified_only",
    "max_findings_per_plugin",
    "request",
}

_DEPRECATED_KEYS = {
    ("scanner", "scope", "blocklist"): "Use scope.exclude_paths instead.",
    ("scanner", "crawler", "respect_robots"): (
        "robots.txt is not treated as an authorization or security boundary; "
        "this option was removed because it was not enforced."
    ),
    ("scanner", "crawler", "dedup"): (
        "Discovery uses deterministic URL/surface fingerprints; the old dedup "
        "selector was removed because it did not change behavior."
    ),
    ("scanner", "request", "user_agent_pool"): (
        "The scanner uses a stable identifiable User-Agent; user_agent_pool was "
        "removed because it was not enforced."
    ),
}


def _mapping(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a mapping")
    return value


def _positive_int(value: Any, name: str, *, allow_zero: bool = False) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    minimum = 0 if allow_zero else 1
    if parsed < minimum:
        comparator = ">= 0" if allow_zero else "> 0"
        raise ValueError(f"{name} must be {comparator}")
    return parsed


def _non_negative_number(value: Any, name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be >= 0")
    return parsed


def validate_config(config: Dict[str, Any]) -> List[str]:
    """Validate release-critical scanner settings and return compatibility warnings."""
    root = _mapping(config, "config")
    scanner = _mapping(root.get("scanner"), "scanner")
    warnings: List[str] = []

    for key in sorted(set(scanner) - _SCANNER_KEYS):
        warnings.append(f"Unknown scanner config key: scanner.{key}")

    for path, message in _DEPRECATED_KEYS.items():
        cursor: Any = root
        present = True
        for part in path:
            if not isinstance(cursor, dict) or part not in cursor:
                present = False
                break
            cursor = cursor[part]
        if present:
            warnings.append(f"Deprecated config key {'.'.join(path)}: {message}")

    scope = _mapping(scanner.get("scope", {}), "scanner.scope")
    for key in ("allowlist", "include_domains", "exclude_paths"):
        value = scope.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"scanner.scope.{key} must be a list of strings")
    for key in ("allow_private", "resolve_dns"):
        if key in scope and not isinstance(scope[key], bool):
            raise ValueError(f"scanner.scope.{key} must be boolean")

    crawler = _mapping(scanner.get("crawler", {}), "scanner.crawler")
    for key in ("max_depth", "max_urls", "max_url_length"):
        if key in crawler:
            _positive_int(crawler[key], f"scanner.crawler.{key}", allow_zero=(key == "max_depth"))

    concurrency = _mapping(scanner.get("concurrency", {}), "scanner.concurrency")
    for key in ("threads", "per_host_concurrency", "timeout", "global_timeout_seconds"):
        if key in concurrency:
            _positive_int(concurrency[key], f"scanner.concurrency.{key}")
    if "max_retries" in concurrency:
        _positive_int(concurrency["max_retries"], "scanner.concurrency.max_retries", allow_zero=True)
    if "delay" in concurrency:
        _non_negative_number(concurrency["delay"], "scanner.concurrency.delay")

    browser = _mapping(scanner.get("browser", {}), "scanner.browser")
    for key in (
        "headless",
        "capture_trace",
        "capture_screenshots",
        "capture_auth_trace",
        "capture_auth_screenshots",
        "retain_storage_state",
    ):
        if key in browser and not isinstance(browser[key], bool):
            raise ValueError(f"scanner.browser.{key} must be boolean")
    if "auth_timeout_seconds" in browser:
        _positive_int(browser["auth_timeout_seconds"], "scanner.browser.auth_timeout_seconds")

    request = _mapping(scanner.get("request", {}), "scanner.request")
    if "max_redirects" in request:
        _positive_int(request["max_redirects"], "scanner.request.max_redirects", allow_zero=True)
    if "max_retries" in request:
        _positive_int(request["max_retries"], "scanner.request.max_retries", allow_zero=True)
    if "follow_redirects" in request and not isinstance(request["follow_redirects"], bool):
        raise ValueError("scanner.request.follow_redirects must be boolean")

    active_checks = _mapping(scanner.get("active_checks", {}), "scanner.active_checks")
    active_web = _mapping(active_checks.get("web", {}), "scanner.active_checks.web")
    for key in ("enabled", "ssti", "crlf", "trace"):
        if key in active_web and not isinstance(active_web[key], bool):
            raise ValueError(f"scanner.active_checks.web.{key} must be boolean")
    for key in ("max_urls", "max_requests"):
        if key in active_web:
            _positive_int(active_web[key], f"scanner.active_checks.web.{key}", allow_zero=True)

    output = _mapping(scanner.get("output", {}), "scanner.output")
    if "directory" in output and not isinstance(output["directory"], str):
        raise ValueError("scanner.output.directory must be a string")

    if "max_findings_per_plugin" in scanner:
        _positive_int(scanner["max_findings_per_plugin"], "scanner.max_findings_per_plugin")
    return warnings
