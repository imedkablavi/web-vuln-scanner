from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(severity: str) -> str:
    value = str(severity or "").upper()
    if value in {"CRITICAL", "HIGH"}:
        return "error"
    if value == "MEDIUM":
        return "warning"
    return "note"


def _rule_id(finding: Dict[str, Any]) -> str:
    plugin = str(finding.get("plugin") or "scanner").strip().replace(" ", "-")
    kind = str(finding.get("type") or finding.get("title") or "finding").strip().lower()
    safe_kind = "-".join(part for part in kind.replace("_", "-").split() if part)
    return f"web-vuln-scanner/{plugin}/{safe_kind or 'finding'}"


def _message(finding: Dict[str, Any]) -> str:
    return str(finding.get("title") or finding.get("type") or "Web security finding")


def _result(finding: Dict[str, Any]) -> Dict[str, Any]:
    url = str(finding.get("url") or "")
    result: Dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _level(finding.get("severity", "")),
        "message": {"text": _message(finding)},
        "properties": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "verificationStatus": finding.get("verification_status"),
            "category": finding.get("category"),
            "plugin": finding.get("plugin"),
            "scannerMode": finding.get("scanner_mode"),
            "remediation": finding.get("remediation"),
        },
    }
    if url:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": url, "uriBaseId": "TARGETROOT"}
                }
            }
        ]
    return result


def _rules(findings: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": str(finding.get("type") or finding.get("plugin") or "finding"),
            "shortDescription": {"text": _message(finding)},
            "help": {"text": str(finding.get("remediation") or "Review and remediate the finding.")},
            "properties": {
                "category": finding.get("category"),
                "plugin": finding.get("plugin"),
            },
        }
    return list(rules.values())


def report_to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = list(report.get("findings") or [])
    scan_info = report.get("scan_info") or {}
    target = str(scan_info.get("target") or "")
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Web Vulnerability Scanner",
                        "informationUri": "https://github.com/imedkablavi/web-vuln-scanner",
                        "version": "0.3.0",
                        "rules": _rules(findings),
                    }
                },
                "originalUriBaseIds": {
                    "TARGETROOT": {"uri": target or "https://target.invalid/"}
                },
                "results": [_result(finding) for finding in findings],
                "properties": {
                    "scanStatus": scan_info.get("status"),
                    "targetClassification": scan_info.get("target_classification"),
                },
            }
        ],
    }


def convert_report(input_path: str | Path, output_path: str | Path | None = None) -> Path:
    source = Path(input_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    destination = Path(output_path) if output_path else source.with_suffix(".sarif")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report_to_sarif(data), indent=2, ensure_ascii=False), encoding="utf-8")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Web Vulnerability Scanner JSON reports to SARIF 2.1.0")
    parser.add_argument("report", help="Path to scan_report.json")
    parser.add_argument("--output", "-o", help="Output SARIF path")
    args = parser.parse_args()
    print(convert_report(args.report, args.output))


if __name__ == "__main__":
    main()
