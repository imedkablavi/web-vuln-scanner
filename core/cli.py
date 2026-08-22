from __future__ import annotations

import importlib.util
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml

from .config_validation import validate_config
from .deadline import install_deadline
from .plugin_catalog import get_plugin_catalog
from .resources import materialize_runtime_config
from .scan_profiles import PROFILES


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
_ACTIVE_WEB_CHECKS = {
    "ssti": {
        "maturity": "stable",
        "activity": "safe-active",
        "cwe": "CWE-1336",
        "wstg": "WSTG-INPV-18",
        "summary": "Two-result arithmetic template evaluation check",
    },
    "crlf": {
        "maturity": "stable",
        "activity": "safe-active",
        "cwe": "CWE-113",
        "wstg": "WSTG-INPV-15",
        "summary": "Response-header canary injection check",
    },
    "trace": {
        "maturity": "stable",
        "activity": "safe-active",
        "cwe": "CWE-16",
        "wstg": "WSTG-CONF-06",
        "summary": "TRACE header reflection check",
    },
}


def _package_version() -> str:
    try:
        return version("web-vuln-scanner")
    except PackageNotFoundError:
        return "0.3.0-dev"


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
    severity_floor = -1 if minimum_severity == "any" else _SEVERITY_RANK[minimum_severity]
    verification_floor = -1 if minimum_verification == "any" else _VERIFICATION_RANK[minimum_verification]
    for finding in findings:
        severity = _SEVERITY_RANK.get(str(finding.get("severity", "")).strip().lower(), -1)
        verification = _VERIFICATION_RANK.get(str(finding.get("verification_status", "")).strip().lower(), -1)
        if severity >= severity_floor and verification >= verification_floor:
            return True
    return False


def _print_rows(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))


def _print_checks() -> None:
    rows: list[tuple[str, ...]] = []
    for name, meta in sorted(get_plugin_catalog().items()):
        rows.append(
            (
                name,
                str(meta.get("maturity", "unknown")),
                str(meta.get("activity", "unknown")),
                ",".join(meta.get("cwe", []) or ["-"]),
                ",".join(meta.get("wstg", []) or ["-"]),
            )
        )
    for name, meta in sorted(_ACTIVE_WEB_CHECKS.items()):
        rows.append((name, meta["maturity"], meta["activity"], meta["cwe"], meta["wstg"]))
    print("Available checks")
    print("Stable checks may run in safe-active/full-authorized. Experimental checks stay blocked by policy.\n")
    _print_rows(("CHECK", "MATURITY", "MODE", "CWE", "WSTG"), rows)


def _print_profiles() -> None:
    descriptions = {
        "passive": "Inventory and posture checks only; no payload injection.",
        "safe-active": "Bounded injection/redirect probes without browser interaction or auth workflows.",
        "full-authorized": "Browser, auth, workflow, and stable active checks for controlled assessments.",
    }
    rows = [(name, descriptions.get(name, "")) for name in sorted(PROFILES)]
    print("Scan profiles\n")
    _print_rows(("PROFILE", "PURPOSE"), rows)


def _doctor() -> int:
    rows: list[tuple[str, ...]] = []
    failures = 0
    try:
        runtime_path = materialize_runtime_config(None)
        with open(runtime_path, "r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        warnings = validate_config(config)
        rows.append(("config", "ok", str(runtime_path)))
        for warning in warnings:
            rows.append(("config warning", "warn", warning))
    except Exception as exc:
        failures += 1
        rows.append(("config", "failed", str(exc)))

    required_modules = ("requests", "bs4", "typer", "yaml")
    for module in required_modules:
        available = importlib.util.find_spec(module) is not None
        failures += 0 if available else 1
        rows.append((module, "ok" if available else "missing", "required"))

    browser_available = importlib.util.find_spec("playwright") is not None
    rows.append(("playwright", "ok" if browser_available else "optional", "needed for browser-assisted profiles"))

    print(f"web-vuln-scanner {_package_version()} diagnostics\n")
    _print_rows(("COMPONENT", "STATUS", "DETAIL"), rows)
    if failures:
        print(f"\nDoctor found {failures} required component problem(s).")
        return 2
    print("\nCore runtime looks ready.")
    return 0


def _print_overview() -> None:
    print(f"web-vuln-scanner {_package_version()}")
    print("Authorized web assessment CLI\n")
    print("Common commands:")
    print("  web-vuln-scanner scan https://target.example --profile passive")
    print("  web-vuln-scanner checks")
    print("  web-vuln-scanner profiles")
    print("  web-vuln-scanner doctor")
    print("\nThe legacy form `web-vuln-scanner https://target.example` still works.")
    print("CI gates: --fail-on-severity <level>  --fail-on-verification <status>\n")


def _handle_meta_command(argv: list[str]) -> bool:
    if len(argv) <= 1:
        return False
    command = argv[1].strip().lower()
    if command in {"version", "--version", "-v"}:
        print(_package_version())
        return True
    if command == "checks":
        _print_checks()
        return True
    if command == "profiles":
        _print_profiles()
        return True
    if command == "doctor":
        raise SystemExit(_doctor())
    if command in {"help", "--help", "-h"}:
        _print_overview()
        if command == "help":
            return True
    return False


def main() -> None:
    if _handle_meta_command(sys.argv):
        return

    if len(sys.argv) > 1 and sys.argv[1].strip().lower() == "scan":
        del sys.argv[1]

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
        if code == 1 and (minimum_severity != "any" or minimum_verification != "any"):
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
