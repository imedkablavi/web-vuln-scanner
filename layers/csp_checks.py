from __future__ import annotations

from typing import Any, Dict, List

from core.models import Finding


def _parse_policy(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for raw_directive in str(value or "").split(";"):
        parts = raw_directive.strip().split()
        if not parts:
            continue
        directives[parts[0].lower()] = parts[1:]
    return directives


def check_csp_policy(snapshot: Dict[str, Any]) -> List[Finding]:
    """Inspect an existing CSP without sending additional requests."""

    if not str(snapshot.get("content_type", "")).lower().startswith("text/html"):
        return []

    headers = {str(k).lower(): str(v) for k, v in (snapshot.get("headers") or {}).items()}
    enforced = headers.get("content-security-policy", "").strip()
    report_only = headers.get("content-security-policy-report-only", "").strip()
    findings: List[Finding] = []

    if not enforced and report_only:
        findings.append(
            Finding(
                plugin="web_posture",
                type="CSP Report-Only Without Enforcement",
                title="Content Security Policy Is Monitoring-Only",
                category="misconfiguration",
                severity="LOW",
                confidence="HIGH",
                surface_id=f"csp-report-only:{snapshot['url']}",
                url=snapshot["url"],
                evidence={
                    "report_only_present": True,
                    "enforced_policy_present": False,
                    "status": snapshot.get("status"),
                },
                remediation="Deploy a tested Content-Security-Policy header in enforcement mode after validating the report-only policy.",
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="passive-web",
                reproducible=True,
                target={
                    "source": "passive-web",
                    "host": snapshot.get("host", ""),
                    "path": snapshot.get("path", "/"),
                },
            )
        )
        return findings

    if not enforced:
        return findings

    directives = _parse_policy(enforced)
    script_sources = directives.get("script-src", directives.get("default-src", []))
    issues: List[str] = []

    normalized_sources = {source.lower() for source in script_sources}
    if "'unsafe-inline'" in normalized_sources:
        issues.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in normalized_sources:
        issues.append("script-src allows 'unsafe-eval'")
    if "*" in normalized_sources:
        issues.append("script-src allows wildcard source *")
    if "data:" in normalized_sources:
        issues.append("script-src allows data: URLs")

    body_lower = str(snapshot.get("text") or "")[:500_000].lower()
    if "<form" in body_lower and "form-action" not in directives:
        issues.append("form-action directive is missing on a page containing forms")

    if not issues:
        return findings

    risky_script = any(issue.startswith("script-src") for issue in issues)
    findings.append(
        Finding(
            plugin="web_posture",
            type="Weak Content Security Policy",
            title="Content Security Policy Contains Risky Directives",
            category="misconfiguration",
            severity="MEDIUM" if risky_script else "LOW",
            confidence="HIGH",
            surface_id=f"csp-weak:{snapshot['url']}",
            url=snapshot["url"],
            evidence={
                "issues": issues,
                "script_src": script_sources[:20],
                "has_default_src": "default-src" in directives,
                "has_frame_ancestors": "frame-ancestors" in directives,
                "has_form_action": "form-action" in directives,
                "status": snapshot.get("status"),
            },
            remediation="Tighten CSP around explicit trusted origins and nonces/hashes. Avoid unsafe script sources and add form-action where forms are present.",
            reproduction={"method": "GET", "url": snapshot["url"]},
            verification_status="detected",
            scanner_mode="passive-web",
            reproducible=True,
            target={
                "source": "passive-web",
                "host": snapshot.get("host", ""),
                "path": snapshot.get("path", "/"),
            },
        )
    )
    return findings
