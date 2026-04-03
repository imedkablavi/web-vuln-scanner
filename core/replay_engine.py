from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse, urlunparse

from .models import AttackSurface, Finding, VerificationScenario
from workflows.scenario_models import WorkflowInstance, WorkflowReplayRecord


class ReplayEngine:
    def __init__(self, requester, *, auth_harness=None, rbac_verifier=None, artifact_store=None, event_bus=None):
        self.requester = requester
        self.auth_harness = auth_harness
        self.rbac_verifier = rbac_verifier
        self.artifact_store = artifact_store
        self.event_bus = event_bus
        self.stats = {
            "attempted": 0,
            "reproduced": 0,
            "failed": 0,
            "workflow_attempted": 0,
            "workflow_reproduced": 0,
            "workflow_replay_partial": 0,
            "workflow_indeterminate": 0,
        }

    def replay_finding(self, finding: Finding) -> Dict[str, Any]:
        self.stats["attempted"] += 1
        scenario = self._scenario_from_finding(finding)
        surface = self._surface_from_finding(finding)
        payload: Dict[str, Any] = {"finding_id": finding.id, "category": finding.category, "url": finding.url}

        try:
            if finding.category == "access-control" and self.rbac_verifier is not None and finding.policy_verdict == "violates_policy_verified":
                result = self.rbac_verifier.verify_access(surface, scenario)
                payload.update(
                    {
                        "mode": "rbac",
                        "decision": result.decision,
                        "policy_verdict": result.policy_verdict,
                        "reproduced": result.decision == "violates_policy_verified",
                        "evidence": result.evidence,
                    }
                )
            elif finding.category == "access-control" and self.auth_harness is not None:
                result = self.auth_harness.verify_access(surface, scenario)
                payload.update(
                    {
                        "mode": "auth_harness",
                        "decision": result.decision,
                        "reproduced": result.decision == "verified",
                        "evidence": result.evidence,
                    }
                )
            else:
                actor = None
                if finding.comparison_actor_id and getattr(self.requester, "auth_session_manager", None) is not None:
                    actor = self.requester.auth_session_manager.get_actor(finding.comparison_actor_id)
                response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload or None, actor=actor, replay_of=finding.id)
                payload.update(
                    {
                        "mode": "http",
                        "decision": "replayed",
                        "reproduced": response is not None and getattr(response, "status_code", 0) < 500,
                        "response": {
                            "status_code": getattr(response, "status_code", 0),
                            "url": getattr(response, "url", surface.url),
                            "excerpt": (getattr(response, "text", "") or "")[:240],
                        },
                    }
                )
        except Exception as exc:
            self.stats["failed"] += 1
            payload.update({"decision": "replay_failed", "reproduced": False, "error": str(exc)})
        else:
            if payload.get("reproduced"):
                self.stats["reproduced"] += 1
            else:
                self.stats["failed"] += 1

        artifact_ref = None
        if self.artifact_store is not None:
            artifact_ref = self.artifact_store.write_json(
                "replay",
                f"{finding.id[:12]}-replay.json",
                payload,
                actor_id=finding.comparison_actor_id or finding.baseline_actor_id,
                finding_id=finding.id,
                description="Replay result",
            )
        if self.event_bus is not None:
            self.event_bus.emit(
                "replay",
                {
                    "finding_id": finding.id,
                    "decision": payload.get("decision"),
                    "reproduced": payload.get("reproduced", False),
                    "artifact_id": artifact_ref.artifact_id if artifact_ref else "",
                },
            )
        return payload | {"artifact_ref": asdict(artifact_ref) if artifact_ref else None}

    def _surface_from_finding(self, finding: Finding) -> AttackSurface:
        parsed = urlparse(finding.url)
        params = {key: values[0] if isinstance(values, list) else values for key, values in parse_qs(parsed.query).items()}
        param_name = str(finding.reproduction.get("param") or finding.target.get("parameter") or finding.evidence.get("param") or "")
        payload = finding.reproduction.get("payload")
        if param_name and payload is not None:
            params[param_name] = str(payload)
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return AttackSurface(
            url=clean_url,
            method=str(finding.target.get("method") or "GET").upper(),
            params=params,
            inputs=[],
            source="replay",
            meta={"finding_id": finding.id},
        )

    def _scenario_from_finding(self, finding: Finding) -> VerificationScenario:
        return VerificationScenario(
            scenario_id=f"replay:{finding.id}",
            url=finding.url,
            method=str(finding.target.get("method") or "GET").upper(),
            source="replay_engine",
            param_name=str(finding.reproduction.get("param") or finding.target.get("parameter") or finding.evidence.get("param") or ""),
            payload=str(finding.reproduction.get("payload") or ""),
            comparison_mode="semantic",
            baseline_actor_id=finding.baseline_actor_id,
            comparison_actor_ids=[finding.comparison_actor_id] if finding.comparison_actor_id else [],
        )

    async def replay_workflow_execution(self, instance: WorkflowInstance, workflow_runner, *, target: str, step_subset: list[str] | None = None) -> Dict[str, Any]:
        self.stats["workflow_attempted"] += 1
        if self.event_bus is not None:
            self.event_bus.emit(
                "workflow_replay_started",
                {
                    "workflow_id": instance.workflow_id,
                    "execution_id": instance.execution_id,
                    "step_ids": list(step_subset or []),
                },
            )

        replay_instance = await workflow_runner.run_definition(
            instance.definition,
            target=target,
            replay_mode=True,
            step_subset=step_subset,
            seed_variables=dict(instance.variable_store.global_values),
        )
        comparison = self._compare_workflow_instances(instance, replay_instance, step_subset=step_subset)
        record = WorkflowReplayRecord(
            workflow_id=instance.workflow_id,
            original_execution_id=instance.execution_id,
            replay_execution_id=replay_instance.execution_id,
            actor_scope=list(dict.fromkeys(instance.actors)),
            steps_replayed=list(step_subset or [step.step_id for step in instance.definition.steps]),
            replay_status=comparison["replay_status"],
            reproduced=bool(comparison["reproduced"]),
            partial_reproduction=bool(comparison["partial_reproduction"]),
            mismatches=list(comparison["mismatches"]),
            artifacts=[],
            policy_context={
                "verification_basis": instance.final_verdict.verification_basis,
                "workflow_status": instance.workflow_status,
            },
        )
        artifact_ref = None
        payload = {
            "workflow_id": instance.workflow_id,
            "original_execution_id": instance.execution_id,
            "replay_execution_id": replay_instance.execution_id,
            "comparison": comparison,
            "original_summary": instance.to_summary(),
            "replay_summary": replay_instance.to_summary(),
        }
        if self.artifact_store is not None:
            artifact_ref = self.artifact_store.write_json(
                "workflow-replay",
                f"{instance.workflow_id}-{instance.execution_id[:8]}-replay",
                payload,
                workflow_id=instance.workflow_id,
                execution_id=instance.execution_id,
                replay_id=replay_instance.execution_id,
                artifact_role="workflow_replay",
                description="Workflow replay result",
            )
            record.artifacts.append(asdict(artifact_ref))
        workflow_runner.record_replay(instance, record)
        if comparison["reproduced"]:
            self.stats["workflow_reproduced"] += 1
        elif comparison["replay_status"] == "replay_partial":
            self.stats["workflow_replay_partial"] += 1
        else:
            self.stats["workflow_indeterminate"] += 1
        if self.event_bus is not None:
            self.event_bus.emit(
                "workflow_replay_finished",
                {
                    "workflow_id": instance.workflow_id,
                    "execution_id": instance.execution_id,
                    "replay_execution_id": replay_instance.execution_id,
                    "outcome": comparison["replay_status"],
                    "artifact_id": artifact_ref.artifact_id if artifact_ref else "",
                },
            )
        return {
            "record": asdict(record),
            "artifact_ref": asdict(artifact_ref) if artifact_ref else None,
            "comparison": comparison,
            "replay_instance": replay_instance.to_summary(),
        }

    def _compare_workflow_instances(self, original: WorkflowInstance, replayed: WorkflowInstance, *, step_subset: list[str] | None = None) -> Dict[str, Any]:
        relevant_step_ids = list(step_subset or [step.step_id for step in original.definition.steps])
        original_steps = original.step_result_map()
        replay_steps = replayed.step_result_map()
        original_checkpoints = {item.checkpoint_id: item for item in original.checkpoint_results}
        replay_checkpoints = {item.checkpoint_id: item for item in replayed.checkpoint_results}
        mismatches = []

        for step_id in relevant_step_ids:
            original_step = original_steps.get(step_id)
            replay_step = replay_steps.get(step_id)
            if original_step is None or replay_step is None:
                mismatches.append({"kind": "step_missing", "step_id": step_id})
                continue
            if original_step.status != replay_step.status:
                mismatches.append({"kind": "step_status", "step_id": step_id, "original": original_step.status, "replay": replay_step.status})

        checkpoint_ids = list(original_checkpoints.keys())
        if not checkpoint_ids:
            return {
                "reproduced": False,
                "partial_reproduction": False,
                "replay_status": "indeterminate",
                "mismatches": [{"kind": "checkpoint_missing", "detail": "original workflow had no checkpoints to compare"}],
            }

        for checkpoint_id in checkpoint_ids:
            original_checkpoint = original_checkpoints.get(checkpoint_id)
            replay_checkpoint = replay_checkpoints.get(checkpoint_id)
            if original_checkpoint is None or replay_checkpoint is None:
                mismatches.append({"kind": "checkpoint_missing", "checkpoint_id": checkpoint_id})
                continue
            if original_checkpoint.status != replay_checkpoint.status or original_checkpoint.outcome != replay_checkpoint.outcome:
                mismatches.append(
                    {
                        "kind": "checkpoint_mismatch",
                        "checkpoint_id": checkpoint_id,
                        "original_status": original_checkpoint.status,
                        "replay_status": replay_checkpoint.status,
                        "original_outcome": original_checkpoint.outcome,
                        "replay_outcome": replay_checkpoint.outcome,
                    }
                )

        if not mismatches and original.final_verdict.decision == replayed.final_verdict.decision:
            return {"reproduced": True, "partial_reproduction": False, "replay_status": "replayed", "mismatches": []}
        if mismatches:
            return {"reproduced": False, "partial_reproduction": True, "replay_status": "replay_partial", "mismatches": mismatches}
        return {"reproduced": False, "partial_reproduction": False, "replay_status": "indeterminate", "mismatches": []}

    def get_summary(self) -> Dict[str, Any]:
        return dict(self.stats)
