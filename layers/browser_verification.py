from __future__ import annotations

from typing import Any, Dict, List

from core.utils import normalize_url


def attach_browser_evidence(findings, browser_report: Dict[str, Any] | None):
    if not browser_report:
        return findings

    page_index: Dict[str, List[Dict[str, Any]]] = {}
    request_index: Dict[str, List[Dict[str, Any]]] = {}

    for snapshot in browser_report.get("pages", []):
        url = normalize_url(snapshot.get("url", ""))
        if url:
            page_index.setdefault(url, []).append(snapshot)

    for request in browser_report.get("requests", []):
        url = normalize_url(request.get("url", ""))
        if url:
            request_index.setdefault(url, []).append(request)

    console_errors = browser_report.get("console_errors", [])

    for finding in findings:
        key = normalize_url(getattr(finding, "url", ""))
        pages = page_index.get(key, [])
        requests = request_index.get(key, [])
        if not pages and not requests:
            continue
        finding.evidence.setdefault("browser", {})
        if pages:
            finding.evidence["browser"]["pages"] = pages[:3]
        if requests:
            finding.evidence["browser"]["requests"] = requests[:5]
        if console_errors:
            finding.evidence["browser"]["console_errors"] = console_errors[:10]
        if not any(note.startswith("Browser evidence attached") for note in finding.notes):
            finding.notes.append("Browser evidence attached from Playwright-assisted discovery.")
    return findings
