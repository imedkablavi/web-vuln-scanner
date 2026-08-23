from __future__ import annotations

import argparse
import json
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Dict, Iterable

from .redaction import redact_structure, redact_text


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _scanner_version() -> str:
    try:
        return version("web-vuln-scanner")
    except PackageNotFoundError:
        return "0.3.0"


def _level(severity: str) -> str:
    value = str(severity or "").upper()
    if value in {"CRITICAL", "HIGH"}:
        return "error"
    if value == "MEDIUM":
        return "warning"
    return "note"


def _slug(value: Any, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    text = re.sub(r"-+", "-", text).strip("-._")
    return text[:120] or fallback


def _rule_id(finding: Dict[str, Any]) -> str:
    plugin = _slug(finding.get("plugin"), "scanner")
    kind = _slug(
        finding.get("type") or finding.get("title"), "finding"
    ).lower()
    return f"web-vuln-scanner/{plugin}/{kind}"


def _message(finding: Dict[str, Any]) -> str:
    return redact_text(
        str(finding.get("title") or finding.get("type") or "Web security finding")
    )


def _result(finding: Dict[str, Any]) -> Dict[str, Any]:
    url = redact_text(str(finding.get("url") or ""))
    properties = redact_structure(
        {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "verificationStatus": finding.get("verification_status"),
            "category": finding.get("category"),
            "plugin": finding.get("plugin"),
            "scannerMode": finding.get("scanner_mode"),
            "remediation": finding.get("remediation"),
            "targetUrl": url,
        }
    )
    result: Dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _level(finding.get("severity", "")),
        "message": {"text": _message(finding)},
        "properties": properties,
    }
    # Web targets are not repository source files. Represent them as logical
    # locations so SARIF consumers do not mistake an HTTP URL for a checkout
    # path while still preserving the target URL for triage.
    if url:
        result["locations"] = [
            {
                "logicalLocations": [
                    {
                        "name": url,
                        "fullyQualifiedName": url,
                        "kind": "web-target",
                    }
                ]
            }
        ]
    return result


def _rules(findings: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        rules[rule_id] = redact_structure(
            {
                "id": rule_id,
                "name": _slug(
                    finding.get("type") or finding.get("plugin"), "finding"
                ),
                "shortDescription": {"text": _message(finding)},
                "help": {
                    "text": redact_text(
                        str(
                            finding.get("remediation")
                            or "Review and remediate the finding."
                        )
                    )
                },
                "properties": {
                    "category": finding.get("category"),
                    "plugin": finding.get("plugin"),
                },
            }
        )
    return list(rules.values())


def report_to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = list(report.get("findings") or [])
    scan_info = report.get("scan_info") or {}
    target = redact_text(str(scan_info.get("target") or ""))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Web Vulnerability Scanner",
                        "informationUri": (
                            "https://github.com/imedkablavi/web-vuln-scanner"
                        ),
                        "version": _scanner_version(),
                        "rules": _rules(findings),
                    }
                },
                "automationDetails": {
                    "id": "web-vuln-scanner/web-target-scan"
                },
                "results": [_result(finding) for finding in findings],
                "properties": redact_structure(
                    {
                        "scanStatus": scan_info.get("status"),
                        "targetClassification": scan_info.get(
                            "target_classification"
                        ),
                        "targetUrl": target,
                    }
                ),
            }
        ],
    }


def convert_report(
    input_path: str | Path, output_path: str | Path | None = None
) -> Path:
    source = Path(input_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    destination = (
        Path(output_path) if output_path else source.with_suffix(".sarif")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report_to_sarif(data), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Web Vulnerability Scanner JSON reports to SARIF 2.1.0"
    )
    parser.add_argument("report", help="Path to scan_report.json")
    parser.add_argument("--output", "-o", help="Output SARIF path")
    args = parser.parse_args()
    print(convert_report(args.report, args.output))


if __name__ == "__main__":
    main()
