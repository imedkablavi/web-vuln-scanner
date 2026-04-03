from __future__ import annotations

import glob
import os
from dataclasses import asdict
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

import yaml

from core.models import AttackSurface, Finding, VerificationScenario
from workflows.scenario_models import (
    WorkflowCheckpoint,
    WorkflowCheckpointResult,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowReplayRecord,
    WorkflowStep,
    WorkflowStepResult,
    WorkflowTransition,
    WorkflowVariableStore,
    WorkflowVerdict,
)
from workflows.step_runner import StepExecutor


class WorkflowRunner:
    def __init__(
        self,
        config: Dict[str, Any],
        *,
        requester,
        auth_session_manager,
        browser_engine=None,
        auth_harness=None,
        rbac_verifier=None,
        event_bus=None,
        artifact_store=None,
    ):
        self.config = config.get("scanner", config)
        self.requester = requester
        self.auth_session_manager = auth_session_manager
        self.browser_engine = browser_engine
        self.auth_harness = auth_harness
        self.rbac_verifier = rbac_verifier
        self.event_bus = event_bus
        self.artifact_store = artifact_store
        self.step_executor = StepExecutor(requester, auth_session_manager=auth_session_manager)
        self.instances: List[WorkflowInstance] = []
        self.stats: Dict[str, Any] = {
            "enabled": bool((self.config.get("workflows", {}) or {}).get("enabled", False)),
            "loaded": 0,
            "attempted": 0,
            "completed": 0,
            "partial": 0,
            "failed": 0,
            "indeterminate": 0,
            "blocked_auth": 0,
            "findings": 0,
            "step_execution_summary": {"total": 0, "completed": 0, "failed": 0, "blocked_auth": 0, "skipped": 0, "indeterminate": 0},
            "checkpoint_summary": {"total": 0, "passed": 0, "failed": 0, "blocked_auth": 0, "skipped": 0, "indeterminate": 0},
            "actor_transition_summary": {"total": 0, "blocked_auth": 0, "actors": {}},
            "partial_executions": [],
            "artifact_refs": [],
            "executions": [],
            "workflow_replay_summary": {"attempted": 0, "replayed": 0, "replay_partial": 0, "failed": 0, "indeterminate": 0},
        }

    def enabled(self) -> bool:
        return bool((self.config.get("workflows", {}) or {}).get("enabled", False))

    def load_definitions(self) -> List[WorkflowDefinition]:
        workflow_cfg = self.config.get("workflows", {}) or {}
        if not workflow_cfg.get("enabled", False):
            return []
        files: List[str] = []
        directory = str(workflow_cfg.get("directory", "") or "").strip()
        if directory:
            files.extend(sorted(glob.glob(os.path.join(directory, "*.yml"))))
            files.extend(sorted(glob.glob(os.path.join(directory, "*.yaml"))))
        files.extend([str(item) for item in (workflow_cfg.get("files", []) or []) if str(item).strip()])

        definitions: List[WorkflowDefinition] = []
        seen = set()
        for path in files:
            full_path = os.path.abspath(path)
            if full_path in seen or not os.path.exists(full_path):
                continue
            seen.add(full_path)
            with open(full_path, "r", encoding="utf-8") as handle:
                raw = yaml.safe_load(handle) or {}
            if not isinstance(raw, dict) or not bool(raw.get("enabled", True)):
                continue
            definition = WorkflowDefinition.from_dict(raw, source_path=full_path)
            if definition.workflow_id and definition.steps:
                definitions.append(definition)
        self.stats["loaded"] = len(definitions)
        return definitions

    async def run_configured(self, target: str) -> Tuple[List[WorkflowInstance], List[Finding]]:
        findings: List[Finding] = []
        definitions = self.load_definitions()
        for definition in definitions:
            instance = await self.run_definition(definition, target=target)
            self.instances.append(instance)
            findings.extend(self._build_findings(instance))
        self.stats["findings"] = len(findings)
        self.stats["executions"] = [instance.to_summary() for instance in self.instances]
        self.stats["artifact_refs"] = [artifact for instance in self.instances for artifact in instance.artifact_refs]
        return self.instances, findings

    async def run_definition(
        self,
        definition: WorkflowDefinition,
        *,
        target: str,
        replay_mode: bool = False,
        step_subset: List[str] | None = None,
        seed_variables: Dict[str, Any] | None = None,
    ) -> WorkflowInstance:
        instance = WorkflowInstance(
            definition=definition,
            workflow_status="running",
            current_actor_id=(definition.actor_sequence[0] if definition.actor_sequence else ""),
            variable_store=WorkflowVariableStore(global_values=dict(seed_variables or {})),
        )
        runtime = {
            "instance": instance,
            "target": target,
            "browser": self.browser_engine,
            "variables": instance.variable_store,
            "current_actor_id": instance.current_actor_id,
            "browser_contexts": {},
            "browser_pages": {},
            "last_http_response": None,
            "last_browser_page": None,
            "last_observation": {},
            "get_actor_page": lambda actor_id, step: self._get_actor_page(runtime, actor_id, step, target),
            "capture_screenshot": lambda page, actor_id, step: self._capture_screenshot(instance, page, actor_id, step),
            "capture_dom": lambda page, actor_id, step: self._capture_dom(instance, page, actor_id, step),
        }
        self.stats["attempted"] += 1
        self._emit("workflow_started", {"workflow_id": definition.workflow_id, "execution_id": instance.execution_id, "actors": definition.actors, "replay_mode": replay_mode})
        try:
            for step in definition.steps:
                if step_subset and step.step_id not in step_subset:
                    continue
                await self._run_step(instance, step, runtime, target=target)
        finally:
            await self._close_browser_runtime(runtime)

        instance.finished_at = _now_iso()
        instance.final_verdict = self._classify_verdict(instance)
        instance.workflow_status = instance.final_verdict.workflow_status
        if self.artifact_store is not None:
            artifact_ref = self.artifact_store.write_json(
                "workflow-execution",
                f"{instance.workflow_id}-{instance.execution_id}",
                instance.to_summary(),
                workflow_id=instance.workflow_id,
                execution_id=instance.execution_id,
                artifact_role="workflow_execution",
                description="Workflow execution summary",
            )
            instance.artifact_refs.append(asdict(artifact_ref))
        self._tally_instance(instance)
        self._emit(
            "workflow_completed" if instance.workflow_status == "completed" else "workflow_failed",
            {
                "workflow_id": definition.workflow_id,
                "execution_id": instance.execution_id,
                "outcome": instance.workflow_status,
                "related_artifact_ids": [artifact.get("artifact_id", "") for artifact in instance.artifact_refs if artifact.get("artifact_id")],
            },
        )
        return instance

    async def _run_step(self, instance: WorkflowInstance, step: WorkflowStep, runtime: Dict[str, Any], *, target: str):
        actor_id = step.actor_id or runtime.get("current_actor_id") or ""
        if step.step_type == "switch_actor":
            self._emit(
                "workflow_step_started",
                {
                    "workflow_id": instance.workflow_id,
                    "execution_id": instance.execution_id,
                    "step_id": step.step_id,
                    "actor_id": actor_id,
                    "outcome": "running",
                },
            )
            result, transition = self._switch_actor(instance, step, runtime)
            instance.step_results.append(result)
            self._emit(
                "workflow_step_finished",
                {
                    "workflow_id": instance.workflow_id,
                    "execution_id": instance.execution_id,
                    "step_id": step.step_id,
                    "actor_id": actor_id,
                    "outcome": result.status,
                    "related_request_ids": [],
                    "related_artifact_ids": [],
                },
            )
            if transition:
                instance.transitions.append(transition)
                self._emit(
                    "workflow_actor_switched",
                    {
                        "workflow_id": instance.workflow_id,
                        "execution_id": instance.execution_id,
                        "step_id": step.step_id,
                        "actor_id": transition.to_actor_id,
                        "outcome": transition.status,
                    },
                )
            return

        resolved_target = self._resolve_target(target, instance.variable_store.render(step.target, actor_id=actor_id))
        step = WorkflowStep(
            step_id=step.step_id,
            step_type=step.step_type,
            actor_id=actor_id,
            description=step.description,
            target=resolved_target,
            method=step.method,
            selectors=instance.variable_store.render(step.selectors, actor_id=actor_id),
            input_data=instance.variable_store.render(step.input_data, actor_id=actor_id),
            store_as=step.store_as,
            store_scope=step.store_scope,
            reuse_from=list(step.reuse_from),
            assertion_rules=instance.variable_store.render(step.assertion_rules, actor_id=actor_id),
            preconditions=list(step.preconditions),
            checkpoints=list(step.checkpoints),
            use_browser=step.use_browser,
            timeout_ms=step.timeout_ms,
            enabled=step.enabled,
            metadata=dict(step.metadata),
        )

        if actor_id and step.step_type != "ensure_actor_ready":
            actor_state = self.auth_session_manager.ensure_authenticated(actor_id)
            if actor_state is None or not actor_state.actor_ready:
                result = WorkflowStepResult(
                    step_id=step.step_id,
                    step_type=step.step_type,
                    actor_id=actor_id,
                    status="blocked_auth",
                    target=step.target,
                    notes=["Actor was not ready before step execution."],
                    metadata={"actor_state": actor_state.to_summary() if actor_state is not None else {}},
                )
                instance.step_results.append(result)
                self._emit(
                    "workflow_step_finished",
                    {
                        "workflow_id": instance.workflow_id,
                        "execution_id": instance.execution_id,
                        "step_id": step.step_id,
                        "actor_id": actor_id,
                        "outcome": result.status,
                        "related_request_ids": [],
                        "related_artifact_ids": [],
                    },
                )
                return

        self._emit(
            "workflow_step_started",
            {
                "workflow_id": instance.workflow_id,
                "execution_id": instance.execution_id,
                "step_id": step.step_id,
                "actor_id": actor_id,
                "outcome": "running",
            },
        )
        result = await self.step_executor.execute(instance, step, runtime)
        instance.step_results.append(result)
        for key, value in result.extracted_values.items():
            instance.variable_store.set_value(key, value, actor_id=actor_id, scope=step.store_scope)
        for artifact in result.artifact_refs:
            if artifact not in instance.artifact_refs:
                instance.artifact_refs.append(artifact)
        self._emit(
            "workflow_step_finished",
            {
                "workflow_id": instance.workflow_id,
                "execution_id": instance.execution_id,
                "step_id": step.step_id,
                "actor_id": actor_id,
                "outcome": result.status,
                "related_request_ids": list(result.request_fingerprints),
                "related_artifact_ids": [artifact.get("artifact_id", "") for artifact in result.artifact_refs if artifact.get("artifact_id")],
            },
        )

        checkpoints = list(step.checkpoints)
        implicit = self._implicit_checkpoint(step)
        if implicit is not None:
            checkpoints.append(implicit)
        for checkpoint in checkpoints:
            checkpoint_result = await self._evaluate_checkpoint(instance, step, result, checkpoint, runtime)
            instance.checkpoint_results.append(checkpoint_result)

    def _implicit_checkpoint(self, step: WorkflowStep) -> WorkflowCheckpoint | None:
        if step.step_type not in {"assert_status", "assert_text", "assert_visibility", "assert_denied", "assert_masked", "assert_policy_outcome"}:
            return None
        expected = step.assertion_rules.get("expected")
        if expected is None and step.step_type == "assert_status":
            expected = step.input_data.get("status")
        return WorkflowCheckpoint(
            checkpoint_id=f"{step.step_id}-assertion",
            checkpoint_type=step.step_type,
            expected=expected,
            assertion_rules=dict(step.assertion_rules or {}),
            policy_binding=dict(step.assertion_rules.get("policy_binding", {}) or {}),
            critical=bool(step.metadata.get("critical", True)),
        )

    def _switch_actor(self, instance: WorkflowInstance, step: WorkflowStep, runtime: Dict[str, Any]) -> Tuple[WorkflowStepResult, WorkflowTransition | None]:
        result = WorkflowStepResult(step_id=step.step_id, step_type=step.step_type, actor_id=step.actor_id or "", target=step.target)
        target_actor_id = step.actor_id or str(step.input_data.get("actor_id", "") or "")
        previous_actor_id = runtime.get("current_actor_id", "")
        if not target_actor_id:
            result.status = "failed"
            result.error = "switch_actor step requires actor_id"
            return result, None
        state = self.auth_session_manager.ensure_authenticated(target_actor_id)
        if state is None or not state.actor_ready:
            result.status = "blocked_auth"
            result.notes.append("Target actor was not ready during actor switch.")
            transition = WorkflowTransition(
                step_id=step.step_id,
                from_actor_id=previous_actor_id,
                to_actor_id=target_actor_id,
                status="blocked_auth",
                reason="actor_not_ready",
            )
            return result, transition
        runtime["current_actor_id"] = target_actor_id
        instance.current_actor_id = target_actor_id
        result.status = "completed"
        result.metadata["actor_state"] = state.to_summary()
        transition = WorkflowTransition(step_id=step.step_id, from_actor_id=previous_actor_id, to_actor_id=target_actor_id, status="completed")
        return result, transition

    async def _evaluate_checkpoint(
        self,
        instance: WorkflowInstance,
        step: WorkflowStep,
        step_result: WorkflowStepResult,
        checkpoint: WorkflowCheckpoint,
        runtime: Dict[str, Any],
    ) -> WorkflowCheckpointResult:
        checkpoint_result = WorkflowCheckpointResult(
            checkpoint_id=checkpoint.checkpoint_id,
            step_id=step.step_id,
            actor_id=step_result.actor_id,
            checkpoint_type=checkpoint.checkpoint_type,
            status="pending",
        )
        basis = "heuristic"
        evidence: Dict[str, Any] = {
            "workflow_id": instance.workflow_id,
            "execution_id": instance.execution_id,
            "step_id": step.step_id,
            "step_status": step_result.status,
            "target": step_result.url or step.target,
        }

        if step_result.status == "blocked_auth":
            checkpoint_result.status = "blocked_auth"
            checkpoint_result.outcome = "blocked_auth"
            checkpoint_result.evidence = evidence | {"notes": ["Checkpoint skipped because step was blocked by auth."]}
            checkpoint_result.notes.append("Checkpoint skipped because actor readiness failed.")
            self._emit_checkpoint(instance, checkpoint_result)
            return checkpoint_result

        if checkpoint.checkpoint_type == "assert_status":
            expected = int(checkpoint.expected or checkpoint.assertion_rules.get("expected") or step.assertion_rules.get("expected") or 0)
            observed = int(step_result.metadata.get("observed_status", step_result.status_code or 0))
            checkpoint_result.status = "passed" if observed == expected else "failed"
            checkpoint_result.outcome = "status_match" if checkpoint_result.status == "passed" else "status_mismatch"
            evidence["observed_status"] = observed
            evidence["expected_status"] = expected
        elif checkpoint.checkpoint_type == "assert_text":
            expected = str(checkpoint.expected or checkpoint.assertion_rules.get("expected") or "")
            observed_text = str(step_result.metadata.get("observed_text") or step_result.metadata.get("response_body") or step_result.response_excerpt or "")
            checkpoint_result.status = "passed" if expected.lower() in observed_text.lower() else "failed"
            checkpoint_result.outcome = "text_match" if checkpoint_result.status == "passed" else "text_missing"
            evidence["expected_text"] = expected
            evidence["observed_excerpt"] = observed_text[:240]
        elif checkpoint.checkpoint_type == "assert_visibility":
            expected = bool(checkpoint.expected if checkpoint.expected is not None else checkpoint.assertion_rules.get("expected", True))
            observed = bool(step_result.metadata.get("visible", False))
            checkpoint_result.status = "passed" if observed is expected else "failed"
            checkpoint_result.outcome = "visibility_match" if checkpoint_result.status == "passed" else "visibility_mismatch"
            evidence["expected_visible"] = expected
            evidence["observed_visible"] = observed
        elif checkpoint.checkpoint_type == "assert_denied":
            denial = step_result.metadata.get("denial") or {}
            denied = bool((denial or {}).get("denied", False))
            checkpoint_result.status = "passed" if denied else "failed"
            checkpoint_result.outcome = "deny_observed" if denied else "deny_missing"
            evidence["denial"] = denial
        elif checkpoint.checkpoint_type == "assert_masked":
            markers = list(step_result.metadata.get("masked_markers", []) or [])
            checkpoint_result.status = "passed" if markers else "failed"
            checkpoint_result.outcome = "masked_observed" if markers else "masked_missing"
            evidence["masked_markers"] = markers
        elif checkpoint.checkpoint_type == "assert_policy_outcome":
            basis = "policy-backed"
            if self.rbac_verifier is None:
                checkpoint_result.status = "indeterminate"
                checkpoint_result.outcome = "policy_verifier_missing"
                checkpoint_result.notes.append("RBAC verifier was unavailable.")
            else:
                surface, scenario = self._surface_and_scenario_from_step(instance, step, step_result)
                policy_result = self.rbac_verifier.verify_access(surface, scenario)
                evidence = policy_result.evidence or evidence
                evidence["policy_expected"] = checkpoint.expected or checkpoint.assertion_rules.get("expected")
                if policy_result.decision == "violates_policy_verified":
                    checkpoint_result.status = "failed"
                    checkpoint_result.outcome = "violates_policy_verified"
                elif policy_result.decision == "matches_policy":
                    checkpoint_result.status = "passed"
                    checkpoint_result.outcome = "matches_policy"
                elif policy_result.decision in {"insufficient_setup", "indeterminate", "policy_missing"}:
                    checkpoint_result.status = "indeterminate"
                    checkpoint_result.outcome = policy_result.decision
                    checkpoint_result.notes.extend(policy_result.notes)
                checkpoint_result.notes.extend(policy_result.notes)
        elif checkpoint.checkpoint_type == "proof_access":
            basis = "proof-backed"
            if self.auth_harness is None:
                checkpoint_result.status = "indeterminate"
                checkpoint_result.outcome = "auth_harness_missing"
                checkpoint_result.notes.append("Auth verification harness was unavailable.")
            elif not self.auth_harness.is_ready():
                checkpoint_result.status = "indeterminate"
                checkpoint_result.outcome = "auth_harness_not_ready"
                checkpoint_result.notes.append("Auth verification harness was not ready.")
            else:
                surface, scenario = self._surface_and_scenario_from_step(instance, step, step_result)
                auth_result = self.auth_harness.verify_access(surface, scenario)
                evidence = auth_result.evidence or evidence
                if auth_result.decision == "verified":
                    checkpoint_result.status = "failed"
                    checkpoint_result.outcome = "workflow_verified"
                elif auth_result.decision == "suspected":
                    checkpoint_result.status = "indeterminate"
                    checkpoint_result.outcome = "workflow_suspected"
                else:
                    checkpoint_result.status = "passed"
                    checkpoint_result.outcome = auth_result.decision or "no_issue"
                checkpoint_result.notes.extend(auth_result.notes)
        else:
            checkpoint_result.status = "indeterminate"
            checkpoint_result.outcome = "unsupported_checkpoint"
            checkpoint_result.notes.append(f"Unsupported checkpoint type: {checkpoint.checkpoint_type}")

        checkpoint_result.verification_basis = basis
        checkpoint_result.evidence = evidence
        checkpoint_result.finished_at = _now_iso()
        self._emit_checkpoint(instance, checkpoint_result)
        return checkpoint_result

    def _surface_and_scenario_from_step(self, instance: WorkflowInstance, step: WorkflowStep, step_result: WorkflowStepResult) -> Tuple[AttackSurface, VerificationScenario]:
        parsed = urlparse(step_result.url or step.target)
        params = {key: values[0] if isinstance(values, list) else values for key, values in parse_qs(parsed.query).items()}
        path_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else (step_result.url or step.target)
        scenario_param = ""
        scenario_payload = ""
        parameter_hint = str(step.assertion_rules.get("parameter") or "")
        if parameter_hint and parameter_hint in params:
            scenario_param = parameter_hint
            scenario_payload = str(params[parameter_hint])
        elif params:
            scenario_param = next(iter(params.keys()))
            scenario_payload = str(params[scenario_param])
        surface = AttackSurface(
            url=path_url,
            method=step.method or "GET",
            params=params,
            inputs=[],
            source="workflow",
            meta={"workflow_id": instance.workflow_id, "execution_id": instance.execution_id, "step_id": step.step_id},
        )
        scenario = VerificationScenario(
            scenario_id=f"workflow:{instance.workflow_id}:{instance.execution_id}:{step.step_id}",
            url=step_result.url or step.target,
            method=step.method or "GET",
            source="workflow_runner",
            param_name=scenario_param,
            payload=scenario_payload,
            comparison_mode="semantic",
            baseline_actor_id=str(step.assertion_rules.get("baseline_actor_id") or (instance.definition.actor_sequence[0] if instance.definition.actor_sequence else "")),
            comparison_actor_ids=[step_result.actor_id] if step_result.actor_id else [],
        )
        return surface, scenario

    def _classify_verdict(self, instance: WorkflowInstance) -> WorkflowVerdict:
        checkpoint_map = {item.checkpoint_id: item for item in instance.checkpoint_results}
        if any(item.outcome == "violates_policy_verified" for item in instance.checkpoint_results):
            related = [item.checkpoint_id for item in instance.checkpoint_results if item.outcome == "violates_policy_verified"]
            return WorkflowVerdict(
                workflow_status="completed",
                verification_status="verified",
                verification_basis="policy-backed",
                decision="workflow_policy_verified",
                reproducible=True,
                related_step_ids=[checkpoint_map[item].step_id for item in related if item in checkpoint_map],
                related_checkpoint_ids=related,
                evidence={"checkpoints": [asdict(item) for item in instance.checkpoint_results if item.outcome == "violates_policy_verified"]},
            )
        if any(item.outcome == "workflow_verified" for item in instance.checkpoint_results):
            related = [item.checkpoint_id for item in instance.checkpoint_results if item.outcome == "workflow_verified"]
            return WorkflowVerdict(
                workflow_status="completed",
                verification_status="verified",
                verification_basis="proof-backed",
                decision="workflow_verified",
                reproducible=True,
                related_step_ids=[checkpoint_map[item].step_id for item in related if item in checkpoint_map],
                related_checkpoint_ids=related,
                evidence={"checkpoints": [asdict(item) for item in instance.checkpoint_results if item.outcome == "workflow_verified"]},
            )
        if any(item.outcome == "workflow_suspected" for item in instance.checkpoint_results):
            related = [item.checkpoint_id for item in instance.checkpoint_results if item.outcome == "workflow_suspected"]
            return WorkflowVerdict(
                workflow_status="indeterminate",
                verification_status="suspected",
                verification_basis="proof-backed",
                decision="workflow_suspected",
                reproducible=False,
                related_step_ids=[checkpoint_map[item].step_id for item in related if item in checkpoint_map],
                related_checkpoint_ids=related,
                evidence={"checkpoints": [asdict(item) for item in instance.checkpoint_results if item.outcome == "workflow_suspected"]},
            )
        if any(item.status == "blocked_auth" for item in instance.step_results):
            return WorkflowVerdict(
                workflow_status="partial",
                verification_status="informational",
                verification_basis="heuristic",
                decision="blocked_auth",
                reproducible=False,
                related_step_ids=[item.step_id for item in instance.step_results if item.status == "blocked_auth"],
                notes=["Workflow execution was partial because one or more actors were not ready."],
            )
        if any(item.status == "failed" for item in instance.step_results):
            return WorkflowVerdict(
                workflow_status="failed",
                verification_status="informational",
                verification_basis="heuristic",
                decision="step_failed",
                reproducible=False,
                related_step_ids=[item.step_id for item in instance.step_results if item.status == "failed"],
                notes=["Workflow execution failed at one or more steps."],
            )
        if any(item.status == "indeterminate" for item in instance.checkpoint_results):
            return WorkflowVerdict(
                workflow_status="indeterminate",
                verification_status="informational",
                verification_basis="heuristic",
                decision="checkpoint_indeterminate",
                reproducible=False,
                related_checkpoint_ids=[item.checkpoint_id for item in instance.checkpoint_results if item.status == "indeterminate"],
                notes=["Workflow checkpoints could not be evaluated deterministically."],
            )
        return WorkflowVerdict(
            workflow_status="completed",
            verification_status="informational",
            verification_basis="heuristic",
            decision="no_issue",
            reproducible=False,
            notes=["Workflow completed without a reportable verification failure."],
        )

    def _build_findings(self, instance: WorkflowInstance) -> List[Finding]:
        findings: List[Finding] = []
        if instance.final_verdict.verification_status not in {"verified", "suspected"}:
            return findings
        checkpoint_results = [item for item in instance.checkpoint_results if item.checkpoint_id in instance.final_verdict.related_checkpoint_ids]
        step_map = instance.step_result_map()
        first_step = step_map.get(instance.final_verdict.related_step_ids[0]) if instance.final_verdict.related_step_ids else (instance.step_results[-1] if instance.step_results else None)
        primary_evidence = checkpoint_results[0].evidence if checkpoint_results else {}
        auth_bucket = dict(primary_evidence.get("auth", {}) or {})
        policy_bucket = dict(primary_evidence.get("policy", {}) or {})
        url = ""
        if first_step is not None:
            url = first_step.url or first_step.target
        if not url:
            url = str(primary_evidence.get("target", ""))

        if instance.final_verdict.decision == "workflow_policy_verified":
            title = "Workflow Policy Violation Verified"
            finding_type = "Workflow RBAC Policy Violation"
            severity = "HIGH"
        elif instance.final_verdict.decision == "workflow_verified":
            title = "Workflow Authorization Bypass Verified"
            finding_type = "Workflow Unauthorized Resource Access"
            severity = "HIGH"
        else:
            title = "Workflow Authorization Signal"
            finding_type = "Workflow Access-Control Signal"
            severity = "MEDIUM"

        findings.append(
            Finding(
                plugin="workflow_runner",
                type=finding_type,
                title=title,
                category="access-control",
                severity=severity,
                confidence="HIGH" if instance.final_verdict.verification_status == "verified" else "LOW",
                surface_id=f"workflow:{instance.workflow_id}",
                url=url,
                evidence={
                    "workflow": {
                        "workflow_id": instance.workflow_id,
                        "execution_id": instance.execution_id,
                        "status": instance.workflow_status,
                        "actors": instance.actors,
                        "step_ids": instance.final_verdict.related_step_ids,
                        "checkpoints": [asdict(item) for item in checkpoint_results],
                    }
                }
                | primary_evidence,
                remediation="Review the workflow-specific authorization controls and enforce consistent actor isolation across the affected steps.",
                reproduction={"workflow_id": instance.workflow_id, "execution_id": instance.execution_id, "steps": instance.final_verdict.related_step_ids},
                verification_status=instance.final_verdict.verification_status,
                scanner_mode="workflow",
                reproducible=instance.final_verdict.reproducible,
                actor_comparison=auth_bucket.get("actor_comparison", {}),
                baseline_actor_id=auth_bucket.get("baseline_actor_id", ""),
                comparison_actor_id=auth_bucket.get("comparison_actor_id", ""),
                authorization_signal=auth_bucket.get("authorization_signal", instance.final_verdict.decision),
                auth_state=primary_evidence.get("auth_state", {}),
                login_performed=bool(primary_evidence.get("login_performed", False)),
                refresh_performed=bool(primary_evidence.get("refresh_performed", False)),
                refresh_count=int(primary_evidence.get("refresh_count", 0) or 0),
                actor_ready=bool(primary_evidence.get("actor_ready", True)),
                auth_evidence=auth_bucket,
                session_expiry_state=str(primary_evidence.get("session_expiry_state", "") or ""),
                policy_source=policy_bucket.get("source", ""),
                expected_access=policy_bucket.get("expectations", {}),
                observed_access=primary_evidence.get("observed_access", {}),
                policy_verdict=policy_bucket.get("verdict", ""),
                ownership_context=policy_bucket.get("ownership", {}),
                deterministic_verification=instance.final_verdict.verification_basis == "policy-backed",
                actor_scope=list(primary_evidence.get("actor_scope", instance.actors)),
                browser_login_used=bool(primary_evidence.get("browser_login_used", False)),
                session_origin=str(primary_evidence.get("session_origin", "") or ""),
                workflow_id=instance.workflow_id,
                workflow_execution_id=instance.execution_id,
                workflow_step_ids=list(instance.final_verdict.related_step_ids),
                workflow_checkpoint_results=[asdict(item) for item in checkpoint_results],
                workflow_status=instance.workflow_status,
                workflow_replay_status=instance.replay_records[-1].replay_status if instance.replay_records else "not_replayed",
                verification_basis=instance.final_verdict.verification_basis,
                artifact_refs=list(instance.artifact_refs),
                notes=list(instance.final_verdict.notes),
            )
        )
        return findings

    def _tally_instance(self, instance: WorkflowInstance):
        bucket = self.stats
        bucket[instance.workflow_status] = bucket.get(instance.workflow_status, 0) + 1
        if instance.workflow_status in {"partial", "failed", "indeterminate", "blocked_auth"}:
            bucket["partial_executions"].append(
                {
                    "workflow_id": instance.workflow_id,
                    "execution_id": instance.execution_id,
                    "status": instance.workflow_status,
                    "notes": list(instance.final_verdict.notes),
                    "errors": list(instance.errors),
                }
            )
        for step_result in instance.step_results:
            bucket["step_execution_summary"]["total"] += 1
            bucket["step_execution_summary"][step_result.status] = bucket["step_execution_summary"].get(step_result.status, 0) + 1
        for checkpoint_result in instance.checkpoint_results:
            bucket["checkpoint_summary"]["total"] += 1
            bucket["checkpoint_summary"][checkpoint_result.status] = bucket["checkpoint_summary"].get(checkpoint_result.status, 0) + 1
        for transition in instance.transitions:
            bucket["actor_transition_summary"]["total"] += 1
            bucket["actor_transition_summary"]["actors"][transition.to_actor_id] = bucket["actor_transition_summary"]["actors"].get(transition.to_actor_id, 0) + 1
            if transition.status == "blocked_auth":
                bucket["actor_transition_summary"]["blocked_auth"] += 1

    async def _get_actor_page(self, runtime: Dict[str, Any], actor_id: str, step: WorkflowStep, target: str):
        if self.browser_engine is None:
            raise RuntimeError("Browser engine is not available for workflow browser steps.")
        actor_pages = runtime["browser_pages"]
        if actor_id in actor_pages:
            return actor_pages[actor_id]
        actor = self.auth_session_manager.get_actor(actor_id) if actor_id else None
        context, page = await self.browser_engine.create_actor_page(actor, url=target)
        runtime["browser_contexts"][actor_id] = context
        actor_pages[actor_id] = page
        return page

    async def _capture_screenshot(self, instance: WorkflowInstance, page, actor_id: str, step: WorkflowStep):
        if self.browser_engine is None:
            return {}
        ref = await self.browser_engine.capture_page_screenshot(
            page,
            f"{instance.workflow_id}-{instance.execution_id}-{step.step_id}-{actor_id or 'anon'}",
            actor_id=actor_id,
            workflow_id=instance.workflow_id,
            execution_id=instance.execution_id,
            step_id=step.step_id,
            artifact_role="workflow_step_screenshot",
            metadata={
                "workflow_id": instance.workflow_id,
                "execution_id": instance.execution_id,
                "step_id": step.step_id,
                "artifact_role": "workflow_step_screenshot",
            },
        )
        return self._normalize_artifact_ref(
            ref,
            workflow_id=instance.workflow_id,
            execution_id=instance.execution_id,
            step_id=step.step_id,
            artifact_role="workflow_step_screenshot",
        )

    async def _capture_dom(self, instance: WorkflowInstance, page, actor_id: str, step: WorkflowStep):
        if self.browser_engine is None:
            return {}
        ref = await self.browser_engine.capture_page_dom(
            page,
            f"{instance.workflow_id}-{instance.execution_id}-{step.step_id}-{actor_id or 'anon'}",
            actor_id=actor_id,
            workflow_id=instance.workflow_id,
            execution_id=instance.execution_id,
            step_id=step.step_id,
            artifact_role="workflow_step_dom",
            metadata={
                "workflow_id": instance.workflow_id,
                "execution_id": instance.execution_id,
                "step_id": step.step_id,
                "artifact_role": "workflow_step_dom",
            },
        )
        return self._normalize_artifact_ref(
            ref,
            workflow_id=instance.workflow_id,
            execution_id=instance.execution_id,
            step_id=step.step_id,
            artifact_role="workflow_step_dom",
        )

    async def _close_browser_runtime(self, runtime: Dict[str, Any]):
        for page in runtime.get("browser_pages", {}).values():
            try:
                await page.close()
            except Exception:
                continue
        for context in runtime.get("browser_contexts", {}).values():
            try:
                await context.close()
            except Exception:
                continue

    def _normalize_artifact_ref(self, ref, **overrides) -> Dict[str, Any]:
        if hasattr(ref, "__dataclass_fields__"):
            payload = asdict(ref)
        elif isinstance(ref, dict):
            payload = dict(ref)
        else:
            payload = {}
        payload.update({key: value for key, value in overrides.items() if value})
        return payload

    def _emit(self, kind: str, payload: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.emit(kind, payload)

    def _emit_checkpoint(self, instance: WorkflowInstance, checkpoint_result: WorkflowCheckpointResult):
        self._emit(
            "workflow_checkpoint",
            {
                "workflow_id": instance.workflow_id,
                "execution_id": instance.execution_id,
                "step_id": checkpoint_result.step_id,
                "actor_id": checkpoint_result.actor_id,
                "outcome": checkpoint_result.outcome,
                "checkpoint_id": checkpoint_result.checkpoint_id,
                "related_artifact_ids": [artifact.get("artifact_id", "") for artifact in checkpoint_result.artifact_refs if artifact.get("artifact_id")],
            },
        )

    def _resolve_target(self, target: str, value: str) -> str:
        if not value:
            return target
        if value.startswith(("http://", "https://")):
            return value
        return urljoin(target, value)

    def get_summary(self) -> Dict[str, Any]:
        summary = dict(self.stats)
        summary["executions"] = [instance.to_summary() for instance in self.instances]
        return summary

    def record_replay(self, instance: WorkflowInstance, replay_record: WorkflowReplayRecord):
        instance.replay_records.append(replay_record)
        instance.final_verdict.evidence.setdefault("workflow_replay", []).append(asdict(replay_record))
        summary = self.stats["workflow_replay_summary"]
        summary["attempted"] += 1
        summary[replay_record.replay_status] = summary.get(replay_record.replay_status, 0) + 1


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
