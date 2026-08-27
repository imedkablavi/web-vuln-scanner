from __future__ import annotations

import sys
from importlib import resources


def _has_config_arg(argv: list[str]) -> bool:
    return any(arg == "--config" or arg.startswith("--config=") for arg in argv)


def main() -> None:
    """Console entry point with a wheel-safe default configuration path."""
    if not _has_config_arg(sys.argv[1:]):
        packaged_default = resources.files("config").joinpath("default_config.yaml")
        if packaged_default.is_file():
            sys.argv.extend(["--config", str(packaged_default)])

    from main_v2 import app

    app()


if __name__ == "__main__":
    main()
