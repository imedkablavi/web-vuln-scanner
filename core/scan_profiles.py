from __future__ import annotations

import argparse
from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any, Dict

import yaml


_EXPERIMENTAL_DISABLED = {
    "lfi": {"enabled": False},
    "cmd_injection": {"enabled": False},
}


PROFILES: Dict[str, Dict[str, Any]] = {
    "passive": {
        "scope": {"resolve_dns": True},
        "browser_enabled": False,
        "crawler_enabled": True,
        "auth_verification": {"enabled": False},
        "workflows": {"enabled": False},
        "active_checks": {"web": {"enabled": False}},
        "passive_checks": {
            "data_exposure": {
                "max_probe_paths": 0,
                "inspect_observed_urls": True,
            }
        },
        "plugins": {
            "sqli": {"enabled": False},
            "business_logic": {"enabled": False},
            "xss_reflected": {"enabled": False},
            "open_redirect": {"enabled": False},
            **_EXPERIMENTAL_DISABLED,
        },
    },
    "safe-active": {
        "scope": {"resolve_dns": True},
        "browser_enabled": False,
        "crawler_enabled": True,
        "auth_verification": {"enabled": False},
        "workflows": {"enabled": False},
        "request": {"follow_redirects": False},
        "active_checks": {
            "web": {
                "enabled": True,
                "max_urls": 10,
                "max_requests": 50,
                "ssti": True,
                "crlf": True,
                "trace": True,
            }
        },
        "plugins": {
            "sqli": {
                "enabled": True,
                "time_based": False,
                "max_tests_per_surface": 3,
            },
            "business_logic": {
                "enabled": True,
                "idor": {"max_tests_per_surface": 3},
            },
            "xss_reflected": {
                "enabled": True,
                "max_tests_per_surface": 4,
            },
            "open_redirect": {
                "enabled": True,
                "max_tests_per_surface": 2,
            },
            **_EXPERIMENTAL_DISABLED,
        },
    },
    "full-authorized": {
        "scope": {"resolve_dns": True},
        "browser_enabled": True,
        "crawler_enabled": True,
        "request": {"follow_redirects": False},
        "active_checks": {
            "web": {
                "enabled": True,
                "max_urls": 20,
                "max_requests": 100,
                "ssti": True,
                "crlf": True,
                "trace": True,
            }
        },
        "browser": {
            "interactions": {
                "enabled": False,
                "submit_forms": False,
                "click_selectors": [],
            },
            "capture_auth_trace": False,
            "capture_auth_screenshots": False,
            "retain_storage_state": False,
        },
        "plugins": {
            "sqli": {
                "enabled": True,
                "time_based": False,
                "max_tests_per_surface": 5,
            },
            "business_logic": {
                "enabled": True,
                "idor": {"max_tests_per_surface": 5},
            },
            "xss_reflected": {
                "enabled": True,
                "max_tests_per_surface": 6,
            },
            "open_redirect": {
                "enabled": True,
                "max_tests_per_surface": 3,
            },
            **_EXPERIMENTAL_DISABLED,
        },
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


def apply_profile(config: Dict[str, Any], profile: str) -> Dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile '{profile}'. Choose from: {', '.join(sorted(PROFILES))}"
        )
    result = deepcopy(config)
    scanner = result.setdefault("scanner", {})
    result["scanner"] = _deep_merge(scanner, PROFILES[profile])
    result["scanner"]["profile"] = profile
    return result


def _read_source_config(config_path: str | Path) -> Dict[str, Any]:
    source = Path(config_path)
    if source.exists():
        return yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if str(config_path).replace("\\", "/") == "config/default_config.yaml":
        text = resources.files("config").joinpath("default_config.yaml").read_text(
            encoding="utf-8"
        )
        return yaml.safe_load(text) or {}
    raise FileNotFoundError(f"Config file not found: {config_path}")


def materialize_profile(
    config_path: str | Path,
    profile: str,
    output_path: str | Path,
) -> Path:
    config = _read_source_config(config_path)
    rendered = apply_profile(config, profile)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(rendered, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write one of the built-in scanner profiles to a YAML file."
    )
    parser.add_argument("profile", choices=sorted(PROFILES))
    parser.add_argument("--config", default="config/default_config.yaml")
    parser.add_argument("--output", "-o", default="config/generated_profile.yaml")
    args = parser.parse_args()
    print(materialize_profile(args.config, args.profile, args.output))


if __name__ == "__main__":
    main()
