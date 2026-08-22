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


def _copy_bundled_resources(config: Dict[str, Any], root: Path) -> None:
    scanner = config.setdefault("scanner", {})

    rbac_source = resources.files("config").joinpath("rbac_matrix.yaml")
    if rbac_source.is_file():
        rbac_target = root / "rbac_matrix.yaml"
        rbac_target.write_text(rbac_source.read_text(encoding="utf-8"), encoding="utf-8")
        scanner["rbac_matrix_file"] = str(rbac_target)

    workflow_source = resources.files("workflows").joinpath("default")
    workflow_target = root / "workflows"
    workflow_target.mkdir(mode=0o700, exist_ok=True)
    if workflow_source.is_dir():
        for item in workflow_source.iterdir():
            if item.is_file() and item.name.lower().endswith((".yaml", ".yml")):
                (workflow_target / item.name).write_text(
                    item.read_text(encoding="utf-8"), encoding="utf-8"
                )
    scanner.setdefault("workflows", {})["directory"] = str(workflow_target)


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


def materialize_runtime_config(config_path: str | None = None) -> Path:
    """Create a short-lived config with absolute resource paths for installed CLI use."""
    root = _new_temp_dir()
    if config_path:
        source = Path(config_path).expanduser()
        if not source.exists():
            if str(config_path).replace("\\", "/") != "config/default_config.yaml":
                raise FileNotFoundError(f"Config file not found: {config_path}")
            config = bundled_default_config()
            _copy_bundled_resources(config, root)
        else:
            config = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
            _resolve_user_paths(config, source.resolve().parent)
    else:
        config = bundled_default_config()
        _copy_bundled_resources(config, root)

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