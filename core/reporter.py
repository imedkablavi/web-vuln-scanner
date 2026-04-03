import html
import ipaddress
import json
import os
import re
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
from core.utils import sanitize_config


class Reporter:
    def __init__(self, config, scan_meta=None):
        self.config = config
        self.scan_meta = scan_meta or {}
        self._findings_by_fingerprint: Dict[str, Finding] = {}

    def set_scan_meta(self, scan_meta: Dict[str, Any]):
        self.scan_meta = scan_meta or {}

    def _redact_sensitive(self, value: Any):
        sensitive = re.compile(r"(token|authorization|cookie|set-cookie|password|api-key|secret)", re.IGNORECASE)
        if isinstance(value, dict):
            redacted = {}
            for k, v in value.items():
                if sensitive.search(str(k)):
                    redacted[k] = "***redacted***"
                else:
                    redacted[k] = self._redact_sensitive(v)
            return redacted
        if isinstance(value, list):
            return [self._redact_sensitive(v) for v in value]
        return value

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
        return sorted(self._findings_by_fingerprint.values(), key=self._finding_sort_key)

    def _report_url_cell(self, url: str) -> str:
        display_url = html.escape((url or "").strip())
        if not display_url:
            return "-"

        parsed = urlparse(url.strip())
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            safe_href = html.escape(url.strip(), quote=True)
            return f"<a href=\"{safe_href}\" rel=\"noopener noreferrer\">{display_url}</a>"
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
        current_key = self._finding_sort_key(current)
        candidate_key = self._finding_sort_key(candidate)
        return candidate if candidate_key < current_key else current

    def _merge_finding_records(self, current: Finding, candidate: Finding) -> Finding:
        primary = self._stronger_finding(current, candidate)
        secondary = candidate if primary is current else current

        merged_evidence = deepcopy(primary.evidence)
        alternate_evidence = merged_evidence.setdefault("alternate_evidence", [])
        if secondary.evidence and secondary.evidence != primary.evidence and secondary.evidence not in alternate_evidence:
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
        timestamps["first_seen"] = min(primary.timestamps.get("first_seen", ""), secondary.timestamps.get("first_seen", "") or primary.timestamps.get("first_seen", ""))
        timestamps["last_seen"] = max(primary.timestamps.get("last_seen", ""), secondary.timestamps.get("last_seen", "") or primary.timestamps.get("last_seen", ""))

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
            actor_comparison=deepcopy(primary.actor_comparison or secondary.actor_comparison),
            baseline_actor_id=primary.baseline_actor_id or secondary.baseline_actor_id,
            comparison_actor_id=primary.comparison_actor_id or secondary.comparison_actor_id,
            authorization_signal=primary.authorization_signal or secondary.authorization_signal,
            auth_state=deepcopy(primary.auth_state or secondary.auth_state),
            login_performed=primary.login_performed or secondary.login_performed,
            refresh_performed=primary.refresh_performed or secondary.refresh_performed,
            refresh_count=max(primary.refresh_count, secondary.refresh_count),
            actor_ready=primary.actor_ready or secondary.actor_ready,
            auth_evidence=deepcopy(primary.auth_evidence or secondary.auth_evidence),
            session_expiry_state=primary.session_expiry_state or secondary.session_expiry_state,
            policy_source=primary.policy_source or secondary.policy_source,
            expected_access=deepcopy(primary.expected_access or secondary.expected_access),
            observed_access=deepcopy(primary.observed_access or secondary.observed_access),
            policy_verdict=primary.policy_verdict or secondary.policy_verdict,
            ownership_context=deepcopy(primary.ownership_context or secondary.ownership_context),
            deterministic_verification=primary.deterministic_verification or secondary.deterministic_verification,
            actor_scope=list(dict.fromkeys(list(primary.actor_scope) + list(secondary.actor_scope))),
            browser_login_used=primary.browser_login_used or secondary.browser_login_used,
            session_origin=primary.session_origin or secondary.session_origin,
            workflow_id=primary.workflow_id or secondary.workflow_id,
            workflow_execution_id=primary.workflow_execution_id or secondary.workflow_execution_id,
            workflow_step_ids=list(dict.fromkeys(list(primary.workflow_step_ids) + list(secondary.workflow_step_ids))),
            workflow_checkpoint_results=list(primary.workflow_checkpoint_results or secondary.workflow_checkpoint_results),
            workflow_status=primary.workflow_status or secondary.workflow_status,
            workflow_replay_status=primary.workflow_replay_status or secondary.workflow_replay_status,
            verification_basis=primary.verification_basis or secondary.verification_basis,
            artifact_refs=merged_artifacts,
            timestamps=timestamps,
            notes=merged_notes,
        )

    def add_finding(self, finding: Finding):
        existing = self._findings_by_fingerprint.get(finding.fingerprint)
        if existing is None:
            self._findings_by_fingerprint[finding.fingerprint] = finding
            return
        self._findings_by_fingerprint[finding.fingerprint] = self._merge_finding_records(existing, finding)

    def _build_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        by_plugin: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_scanner_mode: Dict[str, int] = {}
        for finding in findings:
            by_status[finding.verification_status] = by_status.get(finding.verification_status, 0) + 1
            by_plugin[finding.plugin] = by_plugin.get(finding.plugin, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
            by_scanner_mode[finding.scanner_mode] = by_scanner_mode.get(finding.scanner_mode, 0) + 1
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
            "browser_screenshots": [page.get("screenshot") for page in browser_info.get("pages", []) if page.get("screenshot")],
        }
        layers = execution.get("layers", {})
        workflow_execution = layers.get("workflow_execution", {})
        return {
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
            "auth_sessions": layers.get("auth_sessions", layers.get("auth_verification", {}).get("auth_sessions", {})),
            "browser_login_summary": layers.get("browser_login", {}),
            "rbac_policy_summary": layers.get("rbac_policy", {}),
            "replay_summary": layers.get("replay", {}),
            "workflow_summary": workflow_execution,
            "workflow_replay_summary": workflow_execution.get("workflow_replay_summary", {}),
            "workflow_step_summary": workflow_execution.get("step_execution_summary", {}),
            "workflow_actor_transition_summary": workflow_execution.get("actor_transition_summary", {}),
            "workflow_artifact_index": workflow_execution.get("artifact_refs", []),
            "workflow_failures": workflow_execution.get("partial_executions", []),
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

    def generate_json(self, filename="report.json"):
        findings = self._ordered_findings()
        data = {
            "schema": "webvulnscanner/1.3",
            "scan_info": self._build_scan_info(findings),
            "summary": self._build_summary(findings),
            "config": self._redact_sensitive(sanitize_config(self.config)),
            "findings": [self._finding_to_dict(f) for f in findings],
        }

        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        return filename

    def generate_html(self, filename="report.html"):
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)

        findings = self._ordered_findings()
        verified_only = self.config.get("scanner", {}).get("verified_only", True)
        display_findings = [f for f in findings if f.verification_status == "verified"] if verified_only else findings
        hidden_count = len(findings) - len(display_findings)
        summary = self._build_summary(findings)
        scan_info = self._build_scan_info(findings)

        rows = ""
        for idx, finding in enumerate(display_findings, start=1):
            finding_dict = self._finding_to_dict(finding)
            anchor = f"finding-{idx}"
            rows += f"""
            <tr id=\"{anchor}\" class=\"sev-{finding.severity.lower()} status-{finding.verification_status}\">
                <td>{html.escape(finding.severity)}</td>
                <td>{html.escape(finding.verification_status)}</td>
                <td>{html.escape(finding.confidence)}</td>
                <td>{html.escape(finding.category)}</td>
                <td>{html.escape(finding.scanner_mode)}</td>
                <td>{html.escape(finding.title)}</td>
                <td>{self._report_url_cell(finding.url)}</td>
                <td>{html.escape(finding.plugin)}</td>
                <td>{html.escape(finding.workflow_id or "-")}</td>
                <td>{html.escape(finding.workflow_execution_id or "-")}</td>
                <td>{html.escape(finding.workflow_status or "-")}</td>
                <td>{html.escape(finding.workflow_replay_status or "-")}</td>
                <td>{html.escape(finding.verification_basis or "-")}</td>
                <td>{html.escape(finding.baseline_actor_id or "-")} -> {html.escape(finding.comparison_actor_id or "-")}</td>
                <td>{html.escape(finding.authorization_signal or "-")}</td>
                <td>{html.escape(finding.policy_verdict or "-")}</td>
                <td>{html.escape(str(finding.deterministic_verification).lower())}</td>
                <td>{html.escape(finding.session_origin or "-")}</td>
                <td>{html.escape(str(finding.actor_ready).lower())}</td>
                <td>{html.escape(finding.session_expiry_state or "-")}</td>
                <td>{html.escape(str(finding.reproducible).lower())}</td>
                <td><details><summary>Evidence</summary><pre>{html.escape(json.dumps(finding_dict['evidence'], indent=2, ensure_ascii=False))}</pre></details></td>
                <td><details><summary>Artifacts</summary><pre>{html.escape(json.dumps(finding_dict['artifact_refs'], indent=2, ensure_ascii=False))}</pre></details></td>
                <td><details><summary>Reproduction</summary><pre>{html.escape(json.dumps(finding_dict['reproduction'], indent=2, ensure_ascii=False))}</pre></details></td>
                <td>{html.escape(finding.remediation)}</td>
            </tr>
            """

        warning_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in scan_info["warnings"])
        error_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in scan_info["errors"])
        skipped_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in scan_info["skipped_checks"])
        notes_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in scan_info["notes"])
        artifacts_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in scan_info["artifacts"].get("browser_screenshots", [])[:10])
        summary_json = html.escape(json.dumps(summary, indent=2, ensure_ascii=False))
        layer_json = html.escape(json.dumps(scan_info["layers"], indent=2, ensure_ascii=False))
        auth_json = html.escape(json.dumps(scan_info["auth_verification"], indent=2, ensure_ascii=False))
        auth_sessions_json = html.escape(json.dumps(scan_info["auth_sessions"], indent=2, ensure_ascii=False))
        browser_login_json = html.escape(json.dumps(scan_info["browser_login_summary"], indent=2, ensure_ascii=False))
        rbac_json = html.escape(json.dumps(scan_info["rbac_policy_summary"], indent=2, ensure_ascii=False))
        replay_json = html.escape(json.dumps(scan_info["replay_summary"], indent=2, ensure_ascii=False))
        workflow_json = html.escape(json.dumps(scan_info["workflow_summary"], indent=2, ensure_ascii=False))
        workflow_replay_json = html.escape(json.dumps(scan_info["workflow_replay_summary"], indent=2, ensure_ascii=False))
        workflow_step_json = html.escape(json.dumps(scan_info["workflow_step_summary"], indent=2, ensure_ascii=False))
        workflow_transition_json = html.escape(json.dumps(scan_info["workflow_actor_transition_summary"], indent=2, ensure_ascii=False))
        workflow_artifact_json = html.escape(json.dumps(scan_info["workflow_artifact_index"], indent=2, ensure_ascii=False))
        workflow_failures_json = html.escape(json.dumps(scan_info["workflow_failures"], indent=2, ensure_ascii=False))
        event_bus_json = html.escape(json.dumps(scan_info["event_bus_summary"], indent=2, ensure_ascii=False))
        artifact_index_json = html.escape(json.dumps(scan_info["artifact_index"], indent=2, ensure_ascii=False))

        html_content = f"""
        <!DOCTYPE html>
        <html lang=\"en\">
        <head>
            <meta charset=\"UTF-8\">
            <title>Scan Report - {html.escape(scan_info['target'])}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f9; color: #222; }}
                h1, h2 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; background: #fff; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; vertical-align: top; }}
                th {{ background: #f0f0f0; }}
                .sev-critical {{ background: #ffd9d9; }}
                .sev-high {{ background: #ffe6e6; }}
                .sev-medium {{ background: #fff6e6; }}
                .sev-low {{ background: #e6f0ff; }}
                .sev-info {{ background: #eef3f7; }}
                .status-verified td:nth-child(2) {{ font-weight: 700; color: #0a662e; }}
                .status-detected td:nth-child(2) {{ font-weight: 700; color: #8a4f00; }}
                .status-suspected td:nth-child(2) {{ font-weight: 700; color: #7a1f1f; }}
                .status-informational td:nth-child(2) {{ font-weight: 700; color: #245c7c; }}
                .panel {{ background: #fff; border: 1px solid #ddd; padding: 12px 16px; margin-bottom: 16px; }}
                .muted {{ color: #555; }}
                code, pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
            </style>
        </head>
        <body>
            <h1>Findings ({len(display_findings)})</h1>
            <div class=\"panel\">
                <p><strong>Target:</strong> {html.escape(scan_info['target'])}</p>
                <p><strong>Status:</strong> {html.escape(scan_info['status'])}</p>
                <p><strong>Target classification:</strong> {html.escape(scan_info['target_classification'])}</p>
                <p><strong>Date:</strong> {html.escape(scan_info['timestamp'])}</p>
                <p><strong>Surface count:</strong> {scan_info['surface_count']}</p>
                <p><strong>Collection methods:</strong> {html.escape(', '.join(scan_info['collection_methods']) or 'none')}</p>
                <p><strong>Loaded plugins:</strong> {html.escape(', '.join(scan_info['loaded_plugins']) or 'none')}</p>
                <p class=\"muted\">Verified-only report mode: {html.escape(str(verified_only).lower())}</p>
                <p class=\"muted\">Hidden non-verified findings: {hidden_count}</p>
                <pre>{summary_json}</pre>
            </div>
            <div class=\"panel\">
                <h2>Execution Integrity</h2>
                {f"<ul>{warning_items}</ul>" if warning_items else "<p class='muted'>No warnings recorded.</p>"}
                <h2>Errors</h2>
                {f"<ul>{error_items}</ul>" if error_items else "<p class='muted'>No execution errors recorded.</p>"}
                <h2>Skipped Checks</h2>
                {f"<ul>{skipped_items}</ul>" if skipped_items else "<p class='muted'>No checks were explicitly skipped.</p>"}
                <h2>Notes</h2>
                {f"<ul>{notes_items}</ul>" if notes_items else "<p class='muted'>No additional notes recorded.</p>"}
            </div>
            <div class=\"panel\">
                <h2>Layer Summary</h2>
                <pre>{layer_json}</pre>
                <h2>Auth Verification Summary</h2>
                <pre>{auth_json}</pre>
                <h2>Auth Session Summary</h2>
                <pre>{auth_sessions_json}</pre>
                <h2>Browser Login Summary</h2>
                <pre>{browser_login_json}</pre>
                <h2>RBAC Policy Summary</h2>
                <pre>{rbac_json}</pre>
                <h2>Replay Summary</h2>
                <pre>{replay_json}</pre>
                <h2>Workflow Summary</h2>
                <pre>{workflow_json}</pre>
                <h2>Workflow Replay Summary</h2>
                <pre>{workflow_replay_json}</pre>
                <h2>Step Execution Summary</h2>
                <pre>{workflow_step_json}</pre>
                <h2>Actor Transition Summary</h2>
                <pre>{workflow_transition_json}</pre>
                <h2>Workflow Artifact Index</h2>
                <pre>{workflow_artifact_json}</pre>
                <h2>Workflow Failures / Partial Executions</h2>
                <pre>{workflow_failures_json}</pre>
                <h2>Event Bus Summary</h2>
                <pre>{event_bus_json}</pre>
                <h2>Artifact Index</h2>
                <pre>{artifact_index_json}</pre>
                <h2>Browser Artifacts</h2>
                <p><strong>Trace:</strong> {html.escape(str(scan_info['artifacts'].get('browser_trace') or 'none'))}</p>
                {f"<ul>{artifacts_items}</ul>" if artifacts_items else "<p class='muted'>No browser screenshots captured.</p>"}
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Confidence</th>
                        <th>Category</th>
                        <th>Mode</th>
                        <th>Title</th>
                        <th>URL</th>
                        <th>Plugin</th>
                        <th>Workflow</th>
                        <th>Execution</th>
                        <th>Workflow Status</th>
                        <th>Replay</th>
                        <th>Basis</th>
                        <th>Actor Pair</th>
                        <th>Auth Signal</th>
                        <th>Policy Verdict</th>
                        <th>Deterministic</th>
                        <th>Session Origin</th>
                        <th>Actor Ready</th>
                        <th>Session State</th>
                        <th>Reproducible</th>
                        <th>Evidence</th>
                        <th>Artifacts</th>
                        <th>Reproduction</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else "<tr><td colspan='25' style='text-align:center;font-style:italic;'>No findings matched the current report filter. Review JSON output for detected, suspected, or informational observations.</td></tr>"}
                </tbody>
            </table>
        </body>
        </html>
        """

        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(html_content)
        return filename

    def get_summary(self) -> Dict[str, Any]:
        return self._build_summary(self._ordered_findings())

    def _finding_to_dict(self, finding: Finding):
        return self._redact_sensitive({
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
        })
