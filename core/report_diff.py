from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SEVERITY_RANK = {
    "informational": 0,
    "info": 0,
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


def _canonical_url(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            query,
            "",
        )
    )


def _parameter_hint(finding: Dict[str, Any]) -> str:
    reproduction = finding.get("reproduction") or {}
    target = finding.get("target") or {}
    for key in ("param", "parameter", "input", "field", "name"):
        value = reproduction.get(key)
        if value not in (None, ""):
            return str(value)
        value = target.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Build a stable issue identity that ignores volatile evidence fields."""

    identity = {
        "plugin": str(finding.get("plugin", "")).strip().lower(),
        "type": str(finding.get("type", "")).strip().lower(),
        "title": str(finding.get("title", "")).strip().lower(),
        "url": _canonical_url(str(finding.get("url", ""))),
        "parameter": _parameter_hint(finding).strip().lower(),
        "category": str(finding.get("category", "")).strip().lower(),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _project(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fingerprint": finding_fingerprint(finding),
        "plugin": finding.get("plugin", ""),
        "type": finding.get("type", ""),
        "title": finding.get("title", ""),
        "severity": str(finding.get("severity", "")).upper(),
        "verification_status": str(finding.get("verification_status", "")).lower(),
        "url": _canonical_url(str(finding.get("url", ""))),
        "parameter": _parameter_hint(finding),
    }


def _index(findings: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        indexed.setdefault(finding_fingerprint(finding), finding)
    return indexed


def compare_report_data(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> Dict[str, Any]:
    base = _index(baseline.get("findings") or [])
    now = _index(current.get("findings") or [])

    base_keys = set(base)
    now_keys = set(now)
    new_keys = sorted(now_keys - base_keys)
    fixed_keys = sorted(base_keys - now_keys)
    common_keys = sorted(base_keys & now_keys)

    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []
    for key in common_keys:
        before = _project(base[key])
        after = _project(now[key])
        if (
            before["severity"] != after["severity"]
            or before["verification_status"] != after["verification_status"]
        ):
            changed.append({"fingerprint": key, "before": before, "after": after})
        else:
            unchanged.append(after)

    result = {
        "summary": {
            "baseline_findings": len(base),
            "current_findings": len(now),
            "new": len(new_keys),
            "fixed": len(fixed_keys),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "new": [_project(now[key]) for key in new_keys],
        "fixed": [_project(base[key]) for key in fixed_keys],
        "changed": changed,
        "unchanged": unchanged,
    }
    return result


def compare_report_files(baseline_path: str | Path, current_path: str | Path) -> Dict[str, Any]:
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    current = json.loads(Path(current_path).read_text(encoding="utf-8"))
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("scan reports must contain top-level JSON objects")
    return compare_report_data(baseline, current)


def new_findings_at_or_above(diff: Dict[str, Any], minimum_severity: str) -> List[Dict[str, Any]]:
    normalized = str(minimum_severity or "low").strip().lower()
    if normalized not in _SEVERITY_RANK:
        raise ValueError(f"unsupported severity: {minimum_severity}")
    floor = _SEVERITY_RANK[normalized]
    return [
        item
        for item in diff.get("new", [])
        if _SEVERITY_RANK.get(str(item.get("severity", "")).lower(), -1) >= floor
    ]


def regressions(diff: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return existing findings whose severity or verification strength increased."""

    result = []
    for item in diff.get("changed", []) or []:
        before = item.get("before") or {}
        after = item.get("after") or {}
        severity_worse = _SEVERITY_RANK.get(
            str(after.get("severity", "")).lower(), -1
        ) > _SEVERITY_RANK.get(str(before.get("severity", "")).lower(), -1)
        verification_worse = _VERIFICATION_RANK.get(
            str(after.get("verification_status", "")).lower(), -1
        ) > _VERIFICATION_RANK.get(
            str(before.get("verification_status", "")).lower(), -1
        )
        if severity_worse or verification_worse:
            result.append(item)
    return result
