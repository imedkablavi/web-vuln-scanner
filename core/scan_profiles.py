from __future__ import annotations

import argparse
from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any, Dict

import yaml


PROFILES: Dict[str, Dict[str, Any]] = {
    "passive": {
        "browser_enabled": False,
        "crawler_enabled": True,
        "auth_verification": {"enabled": False},
        "workflows": {"enabled": False},
        "plugins": {
            "sqli": {"enabled": False},
            "business_logic": {"enabled": False},
            "xss_reflected": {"enabled": False},
            "lfi": {"enabled": False},
            "cmd_injection": {"enabled": False},
            "open_redirect": {"enabled": False},
        },
    },
    "safe-active": {
        "browser_enabled": False,
        "crawler_enabled": True,
        "auth_verification": {"enabled": False},
        "workflows": {"enabled": False},
        "plugins": {
            "sqli": {"enabled": True, "time_based": False, "max_tests_per_surface": 3},
            "business_logic": {"enabled": True, "max_tests_per_surface": 3},
            "xss_reflected": {"enabled": False},
            "lfi": {"enabled": False},
            "cmd_injection": {"enabled": False},
            "open_redirect": {"enabled": False},
        },
    },
    "full-authorized": {
        "browser_enabled": True,
        "crawler_enabled": True,
        "plugins": {
            "sqli": {"enabled": True, "time_based": False, "max_tests_per_surface": 5},
            "business_logic": {"enabled": True, "max_tests_per_surface": 5},
            "xss_reflected": {"enabled": False},
            "lfi": {"enabled": False},
            "cmd_injection": {"enabled": False},
            "open_redirect": {"enabled": False},
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
        raise ValueError(f"Unknown profile '{profile}'. Choose from: {', '.join(sorted(PROFILES))}")
    result = deepcopy(config)
    scanner = result.setdefault("scanner", {})
    result["scanner"] = _deep_merge(scanner, PROFILES[profile])
    result["scanner"]["profile"] = profile
    return result


def resolve_config_path(config_path: str | Path) -> Path:
    source = Path(config_path)
    if source.exists():
        return source
    if str(config_path) == "config/default_config.yaml":
        packaged = resources.files("config").joinpath("default_config.yaml")
        if packaged.is_file():
            return Path(str(packaged))
    raise FileNotFoundError(f"Config file not found: {config_path}")


def materialize_profile(config_path: str | Path, profile: str, output_path: str | Path) -> Path:
    source = resolve_config_path(config_path)
    config = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    rendered = apply_profile(config, profile)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(yaml.safe_dump(rendered, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize a conservative scan profile into a scanner config")
    parser.add_argument("profile", choices=sorted(PROFILES))
    parser.add_argument("--config", default="config/default_config.yaml")
    parser.add_argument("--output", "-o", default="config/generated_profile.yaml")
    args = parser.parse_args()
    print(materialize_profile(args.config, args.profile, args.output))


if __name__ == "__main__":
    main()
