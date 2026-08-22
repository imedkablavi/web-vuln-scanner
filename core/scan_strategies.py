from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


# Coverage strategies never enable active checks, auth, browser execution, or
# experimental plugins. They only tune breadth/time budgets for capabilities
# that the selected safety profile has already authorized.
STRATEGIES: Dict[str, Dict[str, Any]] = {
    "lightweight": {
        "crawler": {
            "max_depth": 1,
            "max_urls": 250,
            "discovery_files": {
                "max_sitemap_urls": 100,
                "max_sitemap_files": 3,
                "max_file_bytes": 1_048_576,
            },
            "site_map": {"max_entries": 1000},
            "javascript_discovery": {
                "max_scripts": 4,
                "max_script_bytes": 150_000,
                "max_endpoints": 50,
            },
        },
        "browser": {
            "max_pages": 8,
            "max_actions_per_page": 8,
        },
        "passive_checks": {"web": {"max_urls": 15}},
        "concurrency": {"global_timeout_seconds": 300},
    },
    "balanced": {
        "crawler": {
            "max_depth": 3,
            "max_urls": 2000,
            "discovery_files": {
                "max_sitemap_urls": 500,
                "max_sitemap_files": 10,
                "max_file_bytes": 2_097_152,
            },
            "site_map": {"max_entries": 5000},
            "javascript_discovery": {
                "max_scripts": 10,
                "max_script_bytes": 250_000,
                "max_endpoints": 100,
            },
        },
        "browser": {
            "max_pages": 20,
            "max_actions_per_page": 15,
        },
        "passive_checks": {"web": {"max_urls": 25}},
        "concurrency": {"global_timeout_seconds": 600},
    },
    "deep": {
        "crawler": {
            "max_depth": 5,
            "max_urls": 10_000,
            "discovery_files": {
                "max_sitemap_urls": 5000,
                "max_sitemap_files": 50,
                "max_file_bytes": 4_194_304,
            },
            "site_map": {"max_entries": 20_000},
            "javascript_discovery": {
                "max_scripts": 50,
                "max_script_bytes": 750_000,
                "max_endpoints": 1000,
            },
        },
        "browser": {
            "max_pages": 100,
            "max_actions_per_page": 30,
        },
        "passive_checks": {"web": {"max_urls": 100}},
        "concurrency": {"global_timeout_seconds": 3600},
    },
}


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _int_budget(mapping: Dict[str, Any], key: str, default: int) -> int:
    try:
        return max(0, int(mapping.get(key, default) or default))
    except (TypeError, ValueError):
        return default


def _scale_authorized_budgets(scanner: Dict[str, Any], selected: str) -> None:
    """Scale breadth only for checks already enabled by the safety profile."""
    active = scanner.get("active_checks", {}) or {}
    web = active.get("web", {}) or {}
    if isinstance(web, dict) and web.get("enabled", False):
        current_urls = _int_budget(web, "max_urls", 10)
        current_params = _int_budget(web, "max_params_per_url", 3)
        current_requests = _int_budget(web, "max_requests", 50)
        if selected == "lightweight":
            web["max_urls"] = min(current_urls, 5)
            web["max_params_per_url"] = min(current_params, 2)
            web["max_requests"] = min(current_requests, 25)
        elif selected == "deep":
            web["max_urls"] = max(current_urls, current_urls * 3)
            web["max_params_per_url"] = max(current_params, 5)
            web["max_requests"] = max(current_requests, current_requests * 3)

    templates = active.get("templates", {}) or {}
    if isinstance(templates, dict) and templates.get("enabled", False):
        current_templates = _int_budget(templates, "max_templates", 10)
        current_requests = _int_budget(templates, "max_requests", 10)
        if selected == "lightweight":
            templates["max_templates"] = min(current_templates, 5)
            templates["max_requests"] = min(current_requests, 5)
        elif selected == "deep":
            templates["max_templates"] = max(current_templates, current_templates * 3)
            templates["max_requests"] = max(current_requests, current_requests * 3)

    browser = scanner.get("browser", {}) or {}
    xss = browser.get("xss_verification", {}) or {}
    if isinstance(xss, dict) and xss.get("enabled", False):
        current_tests = _int_budget(xss, "max_tests", 3)
        if selected == "lightweight":
            xss["max_tests"] = min(current_tests, 2)
        elif selected == "deep":
            xss["max_tests"] = max(current_tests, 10)


def apply_strategy(config: Dict[str, Any], strategy: str | None = None) -> Dict[str, Any]:
    result = deepcopy(config)
    scanner = result.setdefault("scanner", {})
    selected = str(
        strategy or scanner.get("strategy", "balanced") or "balanced"
    ).strip().lower()
    if selected not in STRATEGIES:
        raise ValueError(
            f"Unknown scan strategy '{selected}'. Choose from: {', '.join(sorted(STRATEGIES))}"
        )
    result["scanner"] = _deep_merge(scanner, STRATEGIES[selected])
    result["scanner"]["strategy"] = selected
    _scale_authorized_budgets(result["scanner"], selected)
    return result


def strategy_summary(name: str) -> str:
    return {
        "lightweight": "Small discovery and authorized-test budgets for quick feedback.",
        "balanced": "Default coverage budget for routine assessments.",
        "deep": "High discovery and authorized-test budgets for broad assessments.",
    }.get(name, "")
