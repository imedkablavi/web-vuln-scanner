from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from .config_validation import validate_config
from .deadline import install_deadline
from .resources import materialize_runtime_config


_SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_VERIFICATION_RANK = {
    "informational": 0,
    "suspected": 1,
    "detected": 2,
    "verified": 3,
}


def _config_arg(argv: list[str]) -> tuple[str | None, int | None]:
    for index, value in enumerate(argv):
        if value == "--config" and index + 1 < len(argv):
            return argv[index + 1], index + 1
        if value.startswith("--config="):
            return value.split("=", 1)[1], index
    return None, None


def _option_value(argv: list[str], name: str, default: str) -> str:
    for index, value in enumerate(argv):
        if value == name and index + 1 < len(argv):
            return argv[index + 1]
        if value.startswith(f"{name}="):
            return value.split("=", 1)[1]
    return default


def _pop_option(argv: list[str], name: str, default: str) -> str:
    index = 0
    while index < len(argv):
        value = argv[index]
        if value == name:
            if index + 1 >= len(argv):
                raise SystemExit(f"{name} requires a value")
            result = argv[index + 1]
            del argv[index : index + 2]
            return result
        if value.startswith(f"{name}="):
            result = value.split("=", 1)[1]
            del argv[index]
            return result
        index += 1
    return default


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


def _validate_gate_value(value: str, ranks: dict[str, int], option: str) -> str:
    normalized = str(value or "any").strip().lower()
    if normalized != "any" and normalized not in ranks:
        choices = ", ".join(["any", *ranks.keys()])
        raise SystemExit(f"Invalid {option}: {value}. Choose from: {choices}")
    return normalized


def _report_matches_gate(
    report_path: str | Path,
    *,
    minimum_severity: str = "any",
    minimum_verification: str = "any",
) -> bool:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    findings = list(data.get("findings") or [])
    severity_floor = (
        -1 if minimum_severity == "any" else _SEVERITY_RANK[minimum_severity]
    )
    verification_floor = (
        -1
        if minimum_verification == "any"
        else _VERIFICATION_RANK[minimum_verification]
    )
    for finding in findings:
        severity = _SEVERITY_RANK.get(
            str(finding.get("severity", "")).strip().lower(), -1
        )
        verification = _VERIFICATION_RANK.get(
            str(finding.get("verification_status", "")).strip().lower(), -1
        )
        if severity >= severity_floor and verification >= verification_floor:
            return True
    return False


def main() -> None:
    minimum_severity = _validate_gate_value(
        _pop_option(sys.argv, "--fail-on-severity", "any"),
        _SEVERITY_RANK,
        "--fail-on-severity",
    )
    minimum_verification = _validate_gate_value(
        _pop_option(sys.argv, "--fail-on-verification", "any"),
        _VERIFICATION_RANK,
        "--fail-on-verification",
    )

    output_dir = _option_value(sys.argv, "--output", "reports")
    runtime_path = _install_runtime_config(sys.argv)
    with open(runtime_path, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    for warning in validate_config(config):
        print(f"Config warning: {warning}", file=sys.stderr)
    install_deadline(config.get("scanner", {}))

    from main_v2 import app

    try:
        app()
    except SystemExit as exc:
        code = int(exc.code or 0) if isinstance(exc.code, int) else 2
        # Never downgrade runtime/config/partial outcomes. Only refine the
        # completed-with-findings code (1) using the explicit CI gate.
        if code == 1 and (
            minimum_severity != "any" or minimum_verification != "any"
        ):
            report_path = Path(output_dir) / "scan_report.json"
            try:
                should_fail = _report_matches_gate(
                    report_path,
                    minimum_severity=minimum_severity,
                    minimum_verification=minimum_verification,
                )
            except (OSError, ValueError, json.JSONDecodeError) as gate_exc:
                print(f"Unable to evaluate finding gate: {gate_exc}", file=sys.stderr)
                raise SystemExit(2) from gate_exc
            raise SystemExit(1 if should_fail else 0) from None
        raise


if __name__ == "__main__":
    main()
