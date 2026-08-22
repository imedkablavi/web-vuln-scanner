from __future__ import annotations

import html
import ipaddress
import json
import os
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.models import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    VERIFICATION_STATUS_ORDER,
    Finding,
)
from core.redaction import redact_structure
from core.utils import sanitize_config


class Reporter:
    def __init__(self, config, scan_meta=None):
        self.config = config
        self.scan_meta = scan_meta or {}
        self._findings_by_fingerprint: Dict[str, Finding] = {}

    def set_scan_meta(self, scan_meta: Dict[str, Any]):
        self.scan_meta = scan_meta or {}

    def _redact_sensitive(self, value: Any):
        return redact_structure(value)

    def _finding_sort_key(self, finding: Finding):
        return (
            -VERIFICATION_STATUS_ORDER.get(finding.verification_status, 0),
            -SEVERITY_ORDER.get(finding.severity, 0),
            -CONFIDENCE_ORDER.get(finding.confidence, 0),
            finding.category,
            finding.plugin,
            finding.title,
            finding.url,
        )

    def _ordered_findings(self) -> List[Finding]:
        return sorted(
            self._findings_by_fingerprint.values(), key=self._finding_sort_key
        )

    def _report_url_cell(self, url: str) -> str:
        display_url = html.escape((url or "").strip())
        if not display_url:
            return "-"
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            safe_href = html.escape(url.strip(), quote=True)
            return (
                f'<a href="{safe_href}" rel="noopener noreferrer">'
                f"{display_url}</a>"
            )
        return display_url

    def _target_classification(self) -> str:
        target = self.config.get("scanner", {}).get("target", "")
        host = urlparse(target).hostname or ""
        if not host:
            return "unknown"
        if host in {"localhost", "127.0.0.1"}:
            return "local-test"
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return "private-test"
        except ValueError:
            pass
        return "remote"

    def _stronger_finding(self, current: Finding, candidate: Finding) -> Finding:
        return (
            candidate
            if self._finding_sort_key(candidate) < self._finding_sort_key(current)
            else current
        )

    def _merge_finding_records(
        self, current: Finding, candidate: Finding
    ) -> Finding:
        primary = self._stronger_finding(current, candidate)
        secondary = candidate if primary is current else current

        merged_evidence = deepcopy(primary.evidence)
        alternate_evidence = merged_evidence.setdefault("alternate_evidence", [])
        if (
            secondary.evidence
            and secondary.evidence != primary.evidence
            and secondary.evidence not in alternate_evidence
        ):
            alternate_evidence.append(deepcopy(secondary.evidence))
        if not alternate_evidence:
            merged_evidence.pop("alternate_evidence", None)

        merged_notes = []
        for note in list(primary.notes) + list(secondary.notes):
            if note and note not in merged_notes:
                merged_notes.append(note)
        merged_artifacts = []
        for artifact in list(primary.artifact_refs) + list(secondary.artifact_refs):
            if artifact and artifact not in merged_artifacts:
                merged_artifacts.append(deepcopy(artifact))

        timestamps = deepcopy(primary.timestamps)
        first_seen = secondary.timestamps.get("first_seen", "")
        last_seen = secondary.timestamps.get("last_seen", "")
        if first_seen:
            timestamps["first_seen"] = min(
                timestamps.get("first_seen", first_seen), first_seen
            )
        if last_seen:
            timestamps["last_seen"] = max(
                timestamps.get("last_seen", last_seen), last_seen
            )

        return Finding(
            plugin=primary.plugin,
            type=primary.type,
            title=primary.title,
            category=primary.category,
            severity=primary.severity,
            confidence=primary.confidence,
            surface_id=primary.surface_id,
            url=primary.url,
            evidence=merged_evidence,
            remediation=primary.remediation,
            reproduction=deepcopy(primary.reproduction),
            verification_status=primary.verification_status,
            target=deepcopy(primary.target),
            scanner_mode=primary.scanner_mode,
            reproducible=primary.reproducible or secondary.reproducible,
            actor_comparison=deepcopy(
                primary.actor_comparison or secondary.actor_comparison
            ),
            baseline_actor_id=(
                primary.baseline_actor_id or secondary.baseline_actor_id
            ),
            comparison_actor_id=(
                primary.comparison_actor_id or secondary.comparison_actor_id
            ),
            authorization_signal=(
                primary.authorization_signal or secondary.authorization_signal
            ),
            auth_state=deepcopy(primary.auth_state or secondary.auth_state),
            login_performed=primary.login_performed or secondary.login_performed,
            refresh_performed=(
                primary.refresh_performed or secondary.refresh_performed
            ),
            refresh_count=max(primary.refresh_count, secondary.refresh_count),
            actor_ready=primary.actor_ready or secondary.actor_ready,
            auth_evidence=deepcopy(
                primary.auth_evidence or secondary.auth_evidence
            ),
            session_expiry_state=(
                primary.session_expiry_state or secondary.session_expiry_state
            ),
            policy_source=primary.policy_source or secondary.policy_source,
            expected_access=deepcopy(
                primary.expected_access or secondary.expected_access
            ),
            observed_access=deepcopy(
                primary.observed_access or secondary.observed_access
            ),
            policy_verdict=primary.policy_verdict or secondary.policy_verdict,
            ownership_context=deepcopy(
                primary.ownership_context or secondary.ownership_context
            ),
            deterministic_verification=(
                primary.deterministic_verification
                or secondary.deterministic_verification
            ),
            actor_scope=list(
                dict.fromkeys(list(primary.actor_scope) + list(secondary.actor_scope))
            ),
            browser_login_used=(
                primary.browser_login_used or secondary.browser_login_used
            ),
            session_origin=primary.session_origin or secondary.session_origin,
            workflow_id=primary.workflow_id or secondary.workflow_id,
            workflow_execution_id=(
                primary.workflow_execution_id or secondary.workflow_execution_id
            ),
            workflow_step_ids=list(
                dict.fromkeys(
                    list(primary.workflow_step_ids)
                    + list(secondary.workflow_step_ids)
                )
            ),
            workflow_checkpoint_results=list(
                primary.workflow_checkpoint_results
                or secondary.workflow_checkpoint_results
            ),
            workflow_status=primary.workflow_status or secondary.workflow_status,
            workflow_replay_status=(
                primary.workflow_replay_status
                or secondary.workflow_replay_status
            ),
            verification_basis=(
                primary.verification_basis or secondary.verification_basis
            ),
            artifact_refs=merged_artifacts,
            timestamps=timestamps,
            notes=merged_notes,
        )

    def add_finding(self, finding: Finding):
        existing = self._findings_by_fingerprint.get(finding.fingerprint)
        if existing is None:
            self._findings_by_fingerprint[finding.fingerprint] = finding
            return
        self._findings_by_fingerprint[finding.fingerprint] = (
            self._merge_finding_records(existing, finding)
        )

    def _build_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        by_plugin: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_scanner_mode: Dict[str, int] = {}
        for finding in findings:
            by_status[finding.verification_status] = (
                by_status.get(finding.verification_status, 0) + 1
            )
            by_plugin[finding.plugin] = by_plugin.get(finding.plugin, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
            by_scanner_mode[finding.scanner_mode] = (
                by_scanner_mode.get(finding.scanner_mode, 0) + 1
            )
        return {
            "total_findings": len(findings),
            "by_verification_status": by_status,
            "by_plugin": by_plugin,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_scanner_mode": by_scanner_mode,
        }

    def _build_scan_info(self, findings: List[Finding]) -> Dict[str, Any]:
        execution = self.scan_meta.get("execution", {})
        scope = self.config.get("scanner", {}).get("scope", {})
        browser_info = execution.get("browser", {})
        artifacts = {
            "browser_trace": browser_info.get("trace"),
            "browser_artifacts_dir": browser_info.get("artifacts_dir"),
            "browser_screenshots": [
                page.get("screenshot")
                for page in browser_info.get("pages", [])
                if page.get("screenshot")
            ],
        }
        layers = execution.get("layers", {})
        workflow_execution = layers.get("workflow_execution", {})
        info = {
            "target": self.config.get("scanner", {}).get("target", ""),
            "target_classification": self._target_classification(),
            "timestamp": datetime.now().isoformat(),
            "version": "WebVulnScanner layered evidence-first",
            "status": self.scan_meta.get("status", "completed"),
            "surface_count": execution.get("surfaces_discovered", 0),
            "collection_methods": execution.get("collection_methods", []),
            "loaded_plugins": execution.get("loaded_plugins", []),
            "warnings": self.scan_meta.get("warnings", []),
            "errors": self.scan_meta.get("errors", []),
            "notes": self.scan_meta.get("notes", []),
            "skipped_checks": self.scan_meta.get("skipped_checks", []),
            "layers": layers,
            "auth_verification": layers.get("auth_verification", {}),
            "auth_sessions": layers.get(
                "auth_sessions",
                layers.get("auth_verification", {}).get("auth_sessions", {}),
            ),
            "browser_login_summary": layers.get("browser_login", {}),
            "rbac_policy_summary": layers.get("rbac_policy", {}),
            "replay_summary": layers.get("replay", {}),
            "workflow_summary": workflow_execution,
            "workflow_replay_summary": workflow_execution.get(
                "workflow_replay_summary", {}
            ),
            "workflow_step_summary": workflow_execution.get(
                "step_execution_summary", {}
            ),
            "workflow_actor_transition_summary": workflow_execution.get(
                "actor_transition_summary", {}
            ),
            "workflow_artifact_index": workflow_execution.get(
                "artifact_refs", []
            ),
            "workflow_failures": workflow_execution.get(
                "partial_executions", []
            ),
            "event_bus_summary": layers.get("event_bus", {}),
            "artifact_index": layers.get("artifact_index", {}),
            "scope": {
                "allowlist": scope.get("allowlist", []),
                "include_domains": scope.get("include_domains", []),
                "exclude_paths": scope.get("exclude_paths", []),
            },
            "artifacts": artifacts,
            "findings_total": len(findings),
        }
        return self._redact_sensitive(info)

    def generate_json(self, filename="report.json"):
        findings = self._ordered_findings()
        data = {
            "schema": "webvulnscanner/1.4",
            "scan_info": self._build_scan_info(findings),
            "summary": self._build_summary(findings),
            "config": self._redact_sensitive(sanitize_config(self.config)),
            "findings": [self._finding_to_dict(finding) for finding in findings],
        }
        data = self._redact_sensitive(data)
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        try:
            os.chmod(filename, 0o600)
        except OSError:
            pass
        return filename

    def _finding_card(self, finding: Finding, idx: int) -> str:
        item = self._finding_to_dict(finding)
        severity = html.escape(str(item["severity"]).lower())
        status = html.escape(str(item["verification_status"]).lower())
        search_blob = html.escape(
            " ".join(
                str(item.get(key, ""))
                for key in ("title", "plugin", "category", "url", "severity")
            ).lower(),
            quote=True,
        )
        evidence = html.escape(
            json.dumps(item.get("evidence", {}), indent=2, ensure_ascii=False)
        )
        reproduction = html.escape(
            json.dumps(item.get("reproduction", {}), indent=2, ensure_ascii=False)
        )
        artifacts = html.escape(
            json.dumps(item.get("artifact_refs", []), indent=2, ensure_ascii=False)
        )
        actor_pair = " -> ".join(
            part
            for part in (
                item.get("baseline_actor_id", ""),
                item.get("comparison_actor_id", ""),
            )
            if part
        ) or "-"
        return f"""
        <article class="finding" data-severity="{severity}" data-status="{status}" data-search="{search_blob}">
          <div class="finding-head">
            <div>
              <span class="badge sev-{severity}">{html.escape(item['severity'])}</span>
              <span class="badge status-{status}">{html.escape(item['verification_status'])}</span>
              <span class="badge">{html.escape(item['confidence'])}</span>
            </div>
            <code>#{idx}</code>
          </div>
          <h3>{html.escape(item['title'])}</h3>
          <div class="meta-grid">
            <div><strong>URL</strong><span>{self._report_url_cell(item['url'])}</span></div>
            <div><strong>Plugin</strong><span>{html.escape(item['plugin'])}</span></div>
            <div><strong>Category</strong><span>{html.escape(item['category'])}</span></div>
            <div><strong>Mode</strong><span>{html.escape(item['scanner_mode'])}</span></div>
            <div><strong>Actor pair</strong><span>{html.escape(actor_pair)}</span></div>
            <div><strong>Verification basis</strong><span>{html.escape(item.get('verification_basis') or '-')}</span></div>
          </div>
          <p class="remediation"><strong>Remediation:</strong> {html.escape(item['remediation'])}</p>
          <details><summary>Evidence</summary><pre>{evidence}</pre></details>
          <details><summary>Reproduction</summary><pre>{reproduction}</pre></details>
          <details><summary>Artifacts</summary><pre>{artifacts}</pre></details>
        </article>
        """

    def generate_html(self, filename="report.html"):
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        findings = self._ordered_findings()
        verified_only = self.config.get("scanner", {}).get("verified_only", True)
        display_findings = (
            [f for f in findings if f.verification_status == "verified"]
            if verified_only
            else findings
        )
        summary = self._build_summary(findings)
        scan_info = self._build_scan_info(findings)
        cards = "".join(
            self._finding_card(finding, idx)
            for idx, finding in enumerate(display_findings, start=1)
        )
        diagnostics = html.escape(
            json.dumps(scan_info, indent=2, ensure_ascii=False)
        )
        summary_json = html.escape(
            json.dumps(summary, indent=2, ensure_ascii=False)
        )

        severity = summary.get("by_severity", {})
        statuses = summary.get("by_verification_status", {})
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Vulnerability Scan - {html.escape(scan_info['target'])}</title>
<style>
:root {{ color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif; }}
body {{ margin: 0; background: #0b1020; color: #e8edf7; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }}
h1 {{ margin-bottom: 4px; }} h2 {{ margin-top: 28px; }}
a {{ color: #8fc8ff; overflow-wrap: anywhere; }}
.muted {{ color: #aab4c6; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: 12px; margin: 20px 0; }}
.stat, .panel, .finding {{ background: #131b2e; border: 1px solid #29344e; border-radius: 12px; padding: 16px; }}
.stat strong {{ display: block; font-size: 1.7rem; }}
.toolbar {{ display: grid; grid-template-columns: 1fr 180px 180px; gap: 10px; margin: 18px 0; }}
input, select {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #3b4763; background: #0f1628; color: inherit; }}
.finding {{ margin: 12px 0; }} .finding-head {{ display:flex; justify-content:space-between; gap:12px; }}
.badge {{ display:inline-block; padding:3px 8px; margin-right:5px; border-radius:999px; background:#28334c; font-size:.78rem; text-transform:uppercase; }}
.sev-critical {{ background:#7f1d1d; }} .sev-high {{ background:#9a3412; }} .sev-medium {{ background:#854d0e; }} .sev-low {{ background:#1e3a8a; }} .sev-info {{ background:#334155; }}
.status-verified {{ background:#166534; }} .status-detected {{ background:#92400e; }} .status-suspected {{ background:#7f1d1d; }} .status-informational {{ background:#334155; }}
.meta-grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin:12px 0; }}
.meta-grid div {{ display:flex; flex-direction:column; gap:4px; min-width:0; }} .meta-grid span {{ overflow-wrap:anywhere; }}
.remediation {{ line-height:1.5; }} details {{ margin-top:9px; }} summary {{ cursor:pointer; }}
pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#0b1020; padding:12px; border-radius:8px; border:1px solid #25304a; }}
.hidden {{ display:none; }}
@media (max-width: 720px) {{ .toolbar {{ grid-template-columns:1fr; }} main {{ padding:20px 12px 40px; }} }}
</style>
</head>
<body><main>
<h1>Web Vulnerability Scan</h1>
<p class="muted">Evidence-first report. Secrets are redacted before persistence.</p>
<section class="panel">
  <div><strong>Target:</strong> {html.escape(scan_info['target'])}</div>
  <div><strong>Status:</strong> {html.escape(scan_info['status'])}</div>
  <div><strong>Profile:</strong> {html.escape(str(self.scan_meta.get('profile', self.config.get('scanner', {}).get('profile', 'custom'))))}</div>
  <div><strong>Generated:</strong> {html.escape(scan_info['timestamp'])}</div>
</section>
<section class="cards">
  <div class="stat"><span>Total</span><strong>{summary['total_findings']}</strong></div>
  <div class="stat"><span>Verified</span><strong>{statuses.get('verified', 0)}</strong></div>
  <div class="stat"><span>Critical</span><strong>{severity.get('CRITICAL', 0)}</strong></div>
  <div class="stat"><span>High</span><strong>{severity.get('HIGH', 0)}</strong></div>
  <div class="stat"><span>Medium</span><strong>{severity.get('MEDIUM', 0)}</strong></div>
</section>
<h2>Findings</h2>
<div class="toolbar">
  <input id="search" placeholder="Search title, plugin, URL or category">
  <select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
  <select id="status"><option value="">All statuses</option><option>verified</option><option>detected</option><option>suspected</option><option>informational</option></select>
</div>
<div id="findings">{cards or '<div class="panel">No findings matched the configured report filter.</div>'}</div>
<details class="panel"><summary>Execution diagnostics</summary><pre>{diagnostics}</pre></details>
<details class="panel"><summary>Summary JSON</summary><pre>{summary_json}</pre></details>
<script>
const q=document.getElementById('search'), sev=document.getElementById('severity'), status=document.getElementById('status');
function filter() {{
  const term=q.value.toLowerCase().trim(), s=sev.value, st=status.value;
  document.querySelectorAll('.finding').forEach(el => {{
    const visible=(!term || el.dataset.search.includes(term)) && (!s || el.dataset.severity===s) && (!st || el.dataset.status===st);
    el.classList.toggle('hidden', !visible);
  }});
}}
[q,sev,status].forEach(el=>el.addEventListener('input',filter));
</script>
</main></body></html>"""
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(html_content)
        try:
            os.chmod(filename, 0o600)
        except OSError:
            pass
        return filename

    def get_summary(self) -> Dict[str, Any]:
        return self._build_summary(self._ordered_findings())

    def _finding_to_dict(self, finding: Finding):
        value = {
            "id": finding.id,
            "plugin": finding.plugin,
            "title": finding.title,
            "type": finding.type,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "verification_status": finding.verification_status,
            "scanner_mode": finding.scanner_mode,
            "reproducible": finding.reproducible,
            "surface_id": finding.surface_id,
            "target": finding.target,
            "actor_comparison": finding.actor_comparison,
            "baseline_actor_id": finding.baseline_actor_id,
            "comparison_actor_id": finding.comparison_actor_id,
            "authorization_signal": finding.authorization_signal,
            "auth_state": finding.auth_state,
            "login_performed": finding.login_performed,
            "refresh_performed": finding.refresh_performed,
            "refresh_count": finding.refresh_count,
            "actor_ready": finding.actor_ready,
            "auth_evidence": finding.auth_evidence,
            "session_expiry_state": finding.session_expiry_state,
            "policy_source": finding.policy_source,
            "expected_access": finding.expected_access,
            "observed_access": finding.observed_access,
            "policy_verdict": finding.policy_verdict,
            "ownership_context": finding.ownership_context,
            "deterministic_verification": finding.deterministic_verification,
            "actor_scope": finding.actor_scope,
            "browser_login_used": finding.browser_login_used,
            "session_origin": finding.session_origin,
            "workflow_id": finding.workflow_id,
            "workflow_execution_id": finding.workflow_execution_id,
            "workflow_step_ids": finding.workflow_step_ids,
            "workflow_checkpoint_results": finding.workflow_checkpoint_results,
            "workflow_status": finding.workflow_status,
            "workflow_replay_status": finding.workflow_replay_status,
            "verification_basis": finding.verification_basis,
            "artifact_refs": finding.artifact_refs,
            "url": finding.url,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "reproduction": finding.reproduction,
            "timestamps": finding.timestamps,
            "notes": finding.notes,
            "fingerprint": finding.fingerprint,
        }
        return self._redact_sensitive(value)
