from __future__ import annotations

import os
import sys
import time

import yaml

from .config_validation import validate_config
from .resources import materialize_runtime_config


def _config_arg(argv: list[str]) -> tuple[str | None, int | None]:
    for index, value in enumerate(argv):
        if value == "--config" and index + 1 < len(argv):
            return argv[index + 1], index + 1
        if value.startswith("--config="):
            return value.split("=", 1)[1], index
    return None, None


def _install_runtime_config(argv: list[str]) -> str:
    configured, index = _config_arg(argv)
    runtime_path = materialize_runtime_config(configured)
    if index is None:
        argv.extend(["--config", str(runtime_path)])
    elif argv[index].startswith("--config="):
        argv[index] = f"--config={runtime_path}"
    else:
        argv[index] = str(runtime_path)
    return str(runtime_path)


def main() -> None:
    runtime_path = _install_runtime_config(sys.argv)
    config = yaml.safe_load(open(runtime_path, "r", encoding="utf-8")) or {}
    for warning in validate_config(config):
        print(f"Config warning: {warning}", file=sys.stderr)

    timeout = int(
        config.get("scanner", {})
        .get("concurrency", {})
        .get("global_timeout_seconds", 600)
        or 600
    )
    os.environ["WEBVULN_SCAN_DEADLINE_MONOTONIC"] = str(
        time.monotonic() + max(1, timeout)
    )

    from main_v2 import app

    app()
