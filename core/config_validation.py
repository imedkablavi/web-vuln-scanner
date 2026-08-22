from __future__ import annotations

import re
from typing import Any, Dict, List

from .scan_strategies import STRATEGIES


_SCANNER_KEYS = {
    "target",
    "profile",
    "strategy",
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
    "attack_policy",
    "checkpoint",
    "verified_only",
    "max_findings_per_plugin",
    "request",
}

_DEPRECATED_KEYS = {
    ("scanner", "scope", "blocklist"): "Use scope.exclude_paths instead.",
    ("scanner", "crawler", "respect_robots"): (
        "robots.txt is discovery metadata, not an authorization or security boundary. "
        "Use crawler.discovery_files.robots_txt to control whether it is fetched."
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

    strategy = str(scanner.get("strategy", "balanced") or "balanced").strip().lower()
    if strategy not in STRATEGIES:
        raise ValueError(
            f"scanner.strategy must be one of: {', '.join(sorted(STRATEGIES))}"
        )

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
            _positive_int(
                crawler[key],
                f"scanner.crawler.{key}",
                allow_zero=(key == "max_depth"),
            )

    discovery_files = _mapping(
        crawler.get("discovery_files", {}),
        "scanner.crawler.discovery_files",
    )
    for key in ("robots_txt", "sitemap_xml"):
        if key in discovery_files and not isinstance(discovery_files[key], bool):
            raise ValueError(f"scanner.crawler.discovery_files.{key} must be boolean")
    for key in ("max_sitemap_urls", "max_sitemap_files", "max_file_bytes"):
        if key in discovery_files:
            _positive_int(
                discovery_files[key],
                f"scanner.crawler.discovery_files.{key}",
                allow_zero=(key == "max_sitemap_urls"),
            )

    site_map = _mapping(
        crawler.get("site_map", {}),
        "scanner.crawler.site_map",
    )
    if "enabled" in site_map and not isinstance(site_map["enabled"], bool):
        raise ValueError("scanner.crawler.site_map.enabled must be boolean")
    if "output_file" in site_map and not isinstance(site_map["output_file"], str):
        raise ValueError("scanner.crawler.site_map.output_file must be a string")
    if "max_entries" in site_map:
        _positive_int(site_map["max_entries"], "scanner.crawler.site_map.max_entries")

    javascript_discovery = _mapping(
        crawler.get("javascript_discovery", {}),
        "scanner.crawler.javascript_discovery",
    )
    if "enabled" in javascript_discovery and not isinstance(
        javascript_discovery["enabled"], bool
    ):
        raise ValueError("scanner.crawler.javascript_discovery.enabled must be boolean")
    for key in ("max_scripts", "max_endpoints"):
        if key in javascript_discovery:
            _positive_int(
                javascript_discovery[key],
                f"scanner.crawler.javascript_discovery.{key}",
                allow_zero=True,
            )
    if "max_script_bytes" in javascript_discovery:
        _positive_int(
            javascript_discovery["max_script_bytes"],
            "scanner.crawler.javascript_discovery.max_script_bytes",
        )

    har_seed = _mapping(
        crawler.get("har_seed", {}),
        "scanner.crawler.har_seed",
    )
    for key in ("enabled", "active_tests"):
        if key in har_seed and not isinstance(har_seed[key], bool):
            raise ValueError(f"scanner.crawler.har_seed.{key} must be boolean")
    files = har_seed.get("files", [])
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise ValueError("scanner.crawler.har_seed.files must be a list of strings")
    if "max_entries" in har_seed:
        _positive_int(
            har_seed["max_entries"],
            "scanner.crawler.har_seed.max_entries",
        )
    if har_seed.get("enabled", False) and not any(str(item).strip() for item in files):
        raise ValueError(
            "scanner.crawler.har_seed.files requires at least one HAR file when enabled"
        )

    concurrency = _mapping(scanner.get("concurrency", {}), "scanner.concurrency")
    for key in (
        "threads",
        "per_host_concurrency",
        "timeout",
        "global_timeout_seconds",
    ):
        if key in concurrency:
            _positive_int(concurrency[key], f"scanner.concurrency.{key}")
    if "max_retries" in concurrency:
        _positive_int(
            concurrency["max_retries"],
            "scanner.concurrency.max_retries",
            allow_zero=True,
        )
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
        _positive_int(
            browser["auth_timeout_seconds"],
            "scanner.browser.auth_timeout_seconds",
        )
    xss_verification = _mapping(
        browser.get("xss_verification", {}),
        "scanner.browser.xss_verification",
    )
    if "enabled" in xss_verification and not isinstance(
        xss_verification["enabled"], bool
    ):
        raise ValueError("scanner.browser.xss_verification.enabled must be boolean")
    if "max_tests" in xss_verification:
        _positive_int(
            xss_verification["max_tests"],
            "scanner.browser.xss_verification.max_tests",
            allow_zero=True,
        )
    if "timeout_ms" in xss_verification:
        _positive_int(
            xss_verification["timeout_ms"],
            "scanner.browser.xss_verification.timeout_ms",
        )

    request = _mapping(scanner.get("request", {}), "scanner.request")
    if "max_redirects" in request:
        _positive_int(
            request["max_redirects"],
            "scanner.request.max_redirects",
            allow_zero=True,
        )
    if "max_retries" in request:
        _positive_int(
            request["max_retries"],
            "scanner.request.max_retries",
            allow_zero=True,
        )
    if "follow_redirects" in request and not isinstance(
        request["follow_redirects"], bool
    ):
        raise ValueError("scanner.request.follow_redirects must be boolean")

    active_checks = _mapping(
        scanner.get("active_checks", {}),
        "scanner.active_checks",
    )
    active_web = _mapping(
        active_checks.get("web", {}),
        "scanner.active_checks.web",
    )
    for key in ("enabled", "ssti", "crlf", "trace", "ssrf_same_origin"):
        if key in active_web and not isinstance(active_web[key], bool):
            raise ValueError(f"scanner.active_checks.web.{key} must be boolean")
    for key in ("max_urls", "max_params_per_url", "max_requests"):
        if key in active_web:
            _positive_int(
                active_web[key],
                f"scanner.active_checks.web.{key}",
                allow_zero=True,
            )

    active_templates = _mapping(
        active_checks.get("templates", {}),
        "scanner.active_checks.templates",
    )
    for key in ("enabled", "include_builtin"):
        if key in active_templates and not isinstance(active_templates[key], bool):
            raise ValueError(f"scanner.active_checks.templates.{key} must be boolean")
    if "directory" in active_templates and not isinstance(
        active_templates["directory"], str
    ):
        raise ValueError("scanner.active_checks.templates.directory must be a string")
    template_files = active_templates.get("files", [])
    if not isinstance(template_files, list) or not all(
        isinstance(item, str) for item in template_files
    ):
        raise ValueError("scanner.active_checks.templates.files must be a list of strings")
    for key in ("max_templates", "max_requests", "max_body_bytes"):
        if key in active_templates:
            _positive_int(
                active_templates[key],
                f"scanner.active_checks.templates.{key}",
            )

    active_xml = _mapping(
        active_checks.get("xml", {}),
        "scanner.active_checks.xml",
    )
    if "enabled" in active_xml and not isinstance(active_xml["enabled"], bool):
        raise ValueError("scanner.active_checks.xml.enabled must be boolean")
    if "max_requests" in active_xml:
        _positive_int(
            active_xml["max_requests"],
            "scanner.active_checks.xml.max_requests",
            allow_zero=True,
        )

    attack_policy = _mapping(
        scanner.get("attack_policy", {}),
        "scanner.attack_policy",
    )
    for key in ("skip_parameters", "skip_parameter_patterns"):
        value = attack_policy.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"scanner.attack_policy.{key} must be a list of strings")
    for pattern in attack_policy.get("skip_parameter_patterns", []) or []:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"scanner.attack_policy.skip_parameter_patterns contains invalid regex {pattern!r}: {exc}"
            ) from exc

    checkpoint = _mapping(
        scanner.get("checkpoint", {}),
        "scanner.checkpoint",
    )
    for key in ("enabled", "resume", "keep_completed"):
        if key in checkpoint and not isinstance(checkpoint[key], bool):
            raise ValueError(f"scanner.checkpoint.{key} must be boolean")
    if "path" in checkpoint and not isinstance(checkpoint["path"], str):
        raise ValueError("scanner.checkpoint.path must be a string")
    if "flush_every" in checkpoint:
        _positive_int(
            checkpoint["flush_every"],
            "scanner.checkpoint.flush_every",
        )
    if checkpoint.get("resume", False) and not checkpoint.get("enabled", False):
        raise ValueError("scanner.checkpoint.resume requires scanner.checkpoint.enabled=true")
    if checkpoint.get("enabled", False) and not str(checkpoint.get("path", "") or "").strip():
        raise ValueError("scanner.checkpoint.path is required when checkpointing is enabled")

    passive_checks = _mapping(
        scanner.get("passive_checks", {}),
        "scanner.passive_checks",
    )
    passive_web = _mapping(
        passive_checks.get("web", {}),
        "scanner.passive_checks.web",
    )
    if "enabled" in passive_web and not isinstance(passive_web["enabled"], bool):
        raise ValueError("scanner.passive_checks.web.enabled must be boolean")
    if "max_urls" in passive_web:
        _positive_int(
            passive_web["max_urls"],
            "scanner.passive_checks.web.max_urls",
            allow_zero=True,
        )
    if "origin_probe" in passive_web and not isinstance(passive_web["origin_probe"], str):
        raise ValueError("scanner.passive_checks.web.origin_probe must be a string")

    auth_tokens = _mapping(
        passive_checks.get("auth_tokens", {}),
        "scanner.passive_checks.auth_tokens",
    )
    if "enabled" in auth_tokens and not isinstance(auth_tokens["enabled"], bool):
        raise ValueError(
            "scanner.passive_checks.auth_tokens.enabled must be boolean"
        )
    if "max_lifetime_seconds" in auth_tokens:
        _positive_int(
            auth_tokens["max_lifetime_seconds"],
            "scanner.passive_checks.auth_tokens.max_lifetime_seconds",
        )

    output = _mapping(scanner.get("output", {}), "scanner.output")
    if "directory" in output and not isinstance(output["directory"], str):
        raise ValueError("scanner.output.directory must be a string")

    if "max_findings_per_plugin" in scanner:
        _positive_int(
            scanner["max_findings_per_plugin"],
            "scanner.max_findings_per_plugin",
        )
    return warnings