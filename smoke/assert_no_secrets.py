from __future__ import annotations

import argparse
import io
import zipfile
from pathlib import Path
from typing import Iterable


def _scan_bytes(label: str, data: bytes, sentinels: list[bytes]) -> list[str]:
    hits = []
    for sentinel in sentinels:
        if sentinel and sentinel in data:
            hits.append(f"{label}: contains forbidden secret sentinel")
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    if name.endswith("/"):
                        continue
                    hits.extend(
                        _scan_bytes(
                            f"{label}!{name}",
                            archive.read(name),
                            sentinels,
                        )
                    )
        except (OSError, zipfile.BadZipFile, RuntimeError):
            pass
    return hits


def assert_no_secrets(root: Path, values: Iterable[str]) -> None:
    sentinels = [value.encode("utf-8") for value in values if value]
    failures = []
    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = [path for path in root.rglob("*") if path.is_file()]
    else:
        raise FileNotFoundError(root)

    for path in candidates:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        failures.extend(_scan_bytes(str(path), data, sentinels))
    if failures:
        raise RuntimeError(
            "Secret sentinel leakage detected:\n" + "\n".join(failures)
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail when known test secrets are persisted in scan artifacts"
    )
    parser.add_argument("root", type=Path)
    parser.add_argument("secrets", nargs="+")
    args = parser.parse_args()
    assert_no_secrets(args.root, args.secrets)
    print(f"No secret sentinels found under {args.root}")


if __name__ == "__main__":
    main()
