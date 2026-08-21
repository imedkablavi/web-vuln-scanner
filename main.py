"""Legacy compatibility entry point.

The maintained CLI lives in ``main_v2.py`` and is also installed as
``web-vuln-scanner`` through ``pyproject.toml``. This file remains only so old
commands do not break abruptly.
"""

from __future__ import annotations

import sys

from main_v2 import app


def main() -> None:
    print(
        "[deprecated] main.py is retained for compatibility; use main_v2.py or the web-vuln-scanner command.",
        file=sys.stderr,
    )
    if len(sys.argv) > 1 and sys.argv[1].lower() == "scan":
        sys.argv.pop(1)
    app()


if __name__ == "__main__":
    main()
