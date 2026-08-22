from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


# Coverage strategies intentionally do not enable active checks or experimental
# plugins. Safety remains controlled by passive/safe-active/full-authorized.
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


def apply_strategy(config: Dict[str, Any], strategy: str | None = None) -> Dict[str, Any]:
    result = deepcopy(config)
    scanner = result.setdefault("scanner", {})
    selected = str(strategy or scanner.get("strategy", "balanced") or "balanced").strip().lower()
    if selected not in STRATEGIES:
        raise ValueError(
            f"Unknown scan strategy '{selected}'. Choose from: {', '.join(sorted(STRATEGIES))}"
        )
    result["scanner"] = _deep_merge(scanner, STRATEGIES[selected])
    result["scanner"]["strategy"] = selected
    return result


def strategy_summary(name: str) -> str:
    return {
        "lightweight": "Small discovery budget for quick feedback.",
        "balanced": "Default coverage budget for routine assessments.",
        "deep": "High discovery budget for broad authorized application mapping.",
    }.get(name, "")
