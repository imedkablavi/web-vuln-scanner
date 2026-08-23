from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any, Dict

import yaml

from .config_validation import validate_config


_TEMP_DIRS: list[str] = []


def _cleanup_temp_dirs() -> None:
    for path in list(_TEMP_DIRS):
        shutil.rmtree(path, ignore_errors=True)
    _TEMP_DIRS.clear()


atexit.register(_cleanup_temp_dirs)


def _new_temp_dir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="webvuln-config-"))
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    _TEMP_DIRS.append(str(path))
    return path


def bundled_default_config() -> Dict[str, Any]:
    text = resources.files("config").joinpath("default_config.yaml").read_text(
        encoding="utf-8"
    )
    return yaml.safe_load(text) or {}


def _prepare_bundled_runtime_defaults(config: Dict[str, Any]) -> None:
    """Keep installed defaults neutral; assessment policy must come from the user.

    Safe detection templates are loaded directly from package resources by their
    scanner layer. RBAC matrices and workflow scenarios are target-specific and
    therefore are never injected into the installed runtime configuration.
    """
    scanner = config.setdefault("scanner", {})
    scanner.setdefault("rbac_matrix_file", "")
    workflow_cfg = scanner.setdefault("workflows", {})
    workflow_cfg.setdefault("directory", "")
    workflow_cfg.setdefault("files", [])


def _resolve_user_paths(config: Dict[str, Any], base_dir: Path) -> None:
    scanner = config.setdefault("scanner", {})
    rbac_file = str(scanner.get("rbac_matrix_file", "") or "").strip()
    if rbac_file and not os.path.isabs(rbac_file):
        scanner["rbac_matrix_file"] = str((base_dir / rbac_file).resolve())

    workflow_cfg = scanner.setdefault("workflows", {})
    directory = str(workflow_cfg.get("directory", "") or "").strip()
    if directory and not os.path.isabs(directory):
        workflow_cfg["directory"] = str((base_dir / directory).resolve())
    files = []
    for item in workflow_cfg.get("files", []) or []:
        value = str(item)
        files.append(value if os.path.isabs(value) else str((base_dir / value).resolve()))
    workflow_cfg["files"] = files

    crawler_cfg = scanner.setdefault("crawler", {})
    har_seed = crawler_cfg.setdefault("har_seed", {})
    har_files = []
    for item in har_seed.get("files", []) or []:
        value = str(item)
        har_files.append(
            value if os.path.isabs(value) else str((base_dir / value).resolve())
        )
    har_seed["files"] = har_files

    templates_cfg = scanner.setdefault("active_checks", {}).setdefault("templates", {})
    template_directory = str(templates_cfg.get("directory", "") or "").strip()
    if template_directory and not os.path.isabs(template_directory):
        templates_cfg["directory"] = str((base_dir / template_directory).resolve())
    template_files = []
    for item in templates_cfg.get("files", []) or []:
        value = str(item)
        template_files.append(
            value if os.path.isabs(value) else str((base_dir / value).resolve())
        )
    templates_cfg["files"] = template_files


def materialize_runtime_config(config_path: str | None = None) -> Path:
    """Create a short-lived config with absolute user-supplied resource paths."""
    root = _new_temp_dir()
    if config_path:
        source = Path(config_path).expanduser()
        if not source.exists():
            if str(config_path).replace("\\", "/") != "config/default_config.yaml":
                raise FileNotFoundError(f"Config file not found: {config_path}")
            config = bundled_default_config()
            _prepare_bundled_runtime_defaults(config)
        else:
            config = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
            _resolve_user_paths(config, source.resolve().parent)
    else:
        config = bundled_default_config()
        _prepare_bundled_runtime_defaults(config)

    validate_config(config)
    destination = root / "runtime-config.yaml"
    destination.write_text(
        yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
    return destination
