from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


WORKFLOW_STATUSES = {
    "pending",
    "running",
    "completed",
    "partial",
    "failed",
    "indeterminate",
    "blocked_auth",
    "replayed",
    "replay_partial",
}
STEP_STATUSES = {"pending", "running", "completed", "failed", "skipped", "blocked_auth", "indeterminate"}
CHECKPOINT_STATUSES = {"pending", "passed", "failed", "skipped", "blocked_auth", "indeterminate"}
REPLAY_STATUSES = {"not_replayed", "replayed", "replay_partial", "failed", "indeterminate"}

STEP_TYPES = {
    "ensure_actor_ready",
    "visit_url",
    "click",
    "fill",
    "submit",
    "wait_for_url",
    "wait_for_selector",
    "extract_text",
    "extract_attribute",
    "capture_dom",
    "capture_screenshot",
    "api_call",
    "switch_actor",
    "assert_status",
    "assert_text",
    "assert_visibility",
    "assert_masked",
    "assert_denied",
    "assert_policy_outcome",
    "store_value",
    "reuse_value",
}

VAR_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}|\{\s*([a-zA-Z0-9_.-]+)\s*\}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_status(value: str | None, allowed: set[str], default: str) -> str:
    status = (value or default).strip().lower()
    if status not in allowed:
        return default
    return status


@dataclass
class WorkflowCheckpoint:
    checkpoint_id: str
    checkpoint_type: str
    description: str = ""
    expected: Any = None
    assertion_rules: Dict[str, Any] = field(default_factory=dict)
    policy_binding: Dict[str, Any] = field(default_factory=dict)
    actor_scope: List[str] = field(default_factory=list)
    critical: bool = True
    evidence_capture: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "WorkflowCheckpoint":
        return cls(
            checkpoint_id=str(raw.get("checkpoint_id") or raw.get("id") or raw.get("name") or ""),
            checkpoint_type=str(raw.get("checkpoint_type") or raw.get("type") or ""),
            description=str(raw.get("description") or ""),
            expected=raw.get("expected"),
            assertion_rules=dict(raw.get("assertion_rules", {}) or {}),
            policy_binding=dict(raw.get("policy_binding", {}) or {}),
            actor_scope=[str(item) for item in (raw.get("actor_scope", []) or []) if str(item).strip()],
            critical=bool(raw.get("critical", True)),
            evidence_capture=[str(item) for item in (raw.get("evidence_capture", []) or []) if str(item).strip()],
            notes=[str(item) for item in (raw.get("notes", []) or []) if str(item).strip()],
        )


@dataclass
class WorkflowStep:
    step_id: str
    step_type: str
    actor_id: str = ""
    description: str = ""
    target: str = ""
    method: str = "GET"
    selectors: Dict[str, str] = field(default_factory=dict)
    input_data: Dict[str, Any] = field(default_factory=dict)
    store_as: str = ""
    store_scope: str = "global"
    reuse_from: List[str] = field(default_factory=list)
    assertion_rules: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    checkpoints: List[WorkflowCheckpoint] = field(default_factory=list)
    use_browser: bool = False
    timeout_ms: int = 5000
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.step_type = (self.step_type or "").strip().lower()
        if self.step_type not in STEP_TYPES:
            self.step_type = "visit_url"
        self.method = (self.method or "GET").strip().upper()
        self.store_scope = (self.store_scope or "global").strip().lower()
        if self.store_scope not in {"global", "actor"}:
            self.store_scope = "global"
        self.timeout_ms = max(0, int(self.timeout_ms or 0))
        self.reuse_from = [str(item) for item in (self.reuse_from or []) if str(item).strip()]
        self.preconditions = [str(item) for item in (self.preconditions or []) if str(item).strip()]
        self.selectors = {str(key): str(value) for key, value in (self.selectors or {}).items() if str(value).strip()}
        self.input_data = dict(self.input_data or {})
        self.assertion_rules = dict(self.assertion_rules or {})
        self.metadata = dict(self.metadata or {})
        self.checkpoints = [
            checkpoint if isinstance(checkpoint, WorkflowCheckpoint) else WorkflowCheckpoint.from_dict(checkpoint)
            for checkpoint in (self.checkpoints or [])
            if checkpoint
        ]

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "WorkflowStep":
        return cls(
            step_id=str(raw.get("step_id") or raw.get("id") or ""),
            step_type=str(raw.get("step_type") or raw.get("action") or ""),
            actor_id=str(raw.get("actor_id") or ""),
            description=str(raw.get("description") or ""),
            target=str(raw.get("target") or raw.get("url") or ""),
            method=str(raw.get("method") or "GET"),
            selectors=dict(raw.get("selectors", {}) or {}),
            input_data=dict(raw.get("input_data", raw.get("payload", {})) or {}),
            store_as=str(raw.get("store_as") or ""),
            store_scope=str(raw.get("store_scope") or "global"),
            reuse_from=list(raw.get("reuse_from", []) or []),
            assertion_rules=dict(raw.get("assertion_rules", {}) or {}),
            preconditions=list(raw.get("preconditions", []) or []),
            checkpoints=list(raw.get("checkpoints", []) or []),
            use_browser=bool(raw.get("use_browser", False)),
            timeout_ms=int(raw.get("timeout_ms", 5000) or 5000),
            enabled=bool(raw.get("enabled", True)),
            metadata=dict(raw.get("metadata", {}) or {}),
        )


@dataclass
class WorkflowDefinition:
    workflow_id: str
    title: str
    description: str = ""
    replayable: bool = True
    actors: List[str] = field(default_factory=list)
    actor_sequence: List[str] = field(default_factory=list)
    steps: List[WorkflowStep] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    expected_outcomes: Dict[str, Any] = field(default_factory=dict)
    policy_binding: Dict[str, Any] = field(default_factory=dict)
    state_requirements: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_path: str = ""
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self):
        self.actors = [str(item) for item in (self.actors or []) if str(item).strip()]
        self.actor_sequence = [str(item) for item in (self.actor_sequence or []) if str(item).strip()]
        self.preconditions = [str(item) for item in (self.preconditions or []) if str(item).strip()]
        self.expected_outcomes = dict(self.expected_outcomes or {})
        self.policy_binding = dict(self.policy_binding or {})
        self.state_requirements = dict(self.state_requirements or {})
        self.metadata = dict(self.metadata or {})
        self.steps = [step if isinstance(step, WorkflowStep) else WorkflowStep.from_dict(step) for step in (self.steps or []) if step]
        if not self.actor_sequence and self.actors:
            self.actor_sequence = list(self.actors)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], *, source_path: str = "") -> "WorkflowDefinition":
        return cls(
            workflow_id=str(raw.get("workflow_id") or ""),
            title=str(raw.get("title") or raw.get("name") or raw.get("workflow_id") or ""),
            description=str(raw.get("description") or ""),
            replayable=bool(raw.get("replayable", True)),
            actors=[str(item) for item in (raw.get("actors", []) or []) if str(item).strip()],
            actor_sequence=[str(item) for item in (raw.get("actor_sequence", []) or []) if str(item).strip()],
            steps=[WorkflowStep.from_dict(item) for item in (raw.get("steps", []) or []) if isinstance(item, dict)],
            preconditions=[str(item) for item in (raw.get("preconditions", []) or []) if str(item).strip()],
            expected_outcomes=dict(raw.get("expected_outcomes", {}) or {}),
            policy_binding=dict(raw.get("policy_binding", {}) or {}),
            state_requirements=dict(raw.get("state_requirements", {}) or {}),
            metadata=dict(raw.get("metadata", {}) or {}),
            source_path=source_path,
        )


@dataclass
class WorkflowVariableStore:
    global_values: Dict[str, Any] = field(default_factory=dict)
    actor_values: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def set_value(self, key: str, value: Any, *, actor_id: str = "", scope: str = "global"):
        name = str(key or "").strip()
        if not name:
            return
        if (scope or "global").strip().lower() == "actor" and actor_id:
            self.actor_values.setdefault(actor_id, {})[name] = value
            return
        self.global_values[name] = value

    def get_value(self, key: str, *, actor_id: str = "") -> Any:
        name = str(key or "").strip()
        if not name:
            return None
        if name.startswith("actor.") and actor_id:
            _, _, actor_key = name.partition(".")
            return self.actor_values.get(actor_id, {}).get(actor_key)
        if actor_id and name in self.actor_values.get(actor_id, {}):
            return self.actor_values[actor_id][name]
        return self.global_values.get(name)

    def render(self, value: Any, *, actor_id: str = "") -> Any:
        if isinstance(value, str):
            def _replace(match):
                key = match.group(1) or match.group(2) or ""
                resolved = self.get_value(key, actor_id=actor_id)
                return "" if resolved is None else str(resolved)

            return VAR_PATTERN.sub(_replace, value)
        if isinstance(value, list):
            return [self.render(item, actor_id=actor_id) for item in value]
        if isinstance(value, dict):
            return {str(key): self.render(item, actor_id=actor_id) for key, item in value.items()}
        return value

    def to_summary(self) -> Dict[str, Any]:
        return {
            "global_keys": sorted(self.global_values.keys()),
            "actor_keys": {actor_id: sorted(values.keys()) for actor_id, values in self.actor_values.items()},
        }


@dataclass
class WorkflowCheckpointResult:
    checkpoint_id: str
    step_id: str
    actor_id: str = ""
    checkpoint_type: str = ""
    status: str = "pending"
    outcome: str = ""
    verification_basis: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    artifact_refs: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""

    def __post_init__(self):
        self.status = _normalize_status(self.status, CHECKPOINT_STATUSES, "pending")
        self.finished_at = self.finished_at or self.started_at


@dataclass
class WorkflowStepResult:
    step_id: str
    step_type: str
    actor_id: str = ""
    status: str = "pending"
    target: str = ""
    url: str = ""
    status_code: int = 0
    response_excerpt: str = ""
    extracted_values: Dict[str, Any] = field(default_factory=dict)
    request_fingerprints: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    artifact_refs: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""

    def __post_init__(self):
        self.status = _normalize_status(self.status, STEP_STATUSES, "pending")
        self.finished_at = self.finished_at or self.started_at

    @property
    def ok(self) -> bool:
        return self.status == "completed" and not self.error


@dataclass
class WorkflowTransition:
    step_id: str
    from_actor_id: str = ""
    to_actor_id: str = ""
    status: str = "completed"
    reason: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def __post_init__(self):
        self.status = _normalize_status(self.status, STEP_STATUSES, "completed")


@dataclass
class WorkflowVerdict:
    workflow_status: str = "pending"
    verification_status: str = "informational"
    verification_basis: str = "heuristic"
    decision: str = ""
    reproducible: bool = False
    related_step_ids: List[str] = field(default_factory=list)
    related_checkpoint_ids: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.workflow_status = _normalize_status(self.workflow_status, WORKFLOW_STATUSES, "pending")


@dataclass
class WorkflowReplayRecord:
    workflow_id: str
    original_execution_id: str
    replay_execution_id: str = ""
    actor_scope: List[str] = field(default_factory=list)
    steps_replayed: List[str] = field(default_factory=list)
    replay_status: str = "not_replayed"
    reproduced: bool = False
    partial_reproduction: bool = False
    mismatches: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    policy_context: Dict[str, Any] = field(default_factory=dict)
    replay_started_at: str = field(default_factory=_now_iso)
    replay_finished_at: str = ""

    def __post_init__(self):
        self.replay_status = _normalize_status(self.replay_status, REPLAY_STATUSES, "not_replayed")
        self.replay_finished_at = self.replay_finished_at or self.replay_started_at


@dataclass
class WorkflowInstance:
    definition: WorkflowDefinition
    execution_id: str = ""
    workflow_status: str = "pending"
    current_actor_id: str = ""
    step_results: List[WorkflowStepResult] = field(default_factory=list)
    checkpoint_results: List[WorkflowCheckpointResult] = field(default_factory=list)
    transitions: List[WorkflowTransition] = field(default_factory=list)
    variable_store: WorkflowVariableStore = field(default_factory=WorkflowVariableStore)
    artifact_refs: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    final_verdict: WorkflowVerdict = field(default_factory=WorkflowVerdict)
    replay_records: List[WorkflowReplayRecord] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""

    def __post_init__(self):
        self.execution_id = self.execution_id or hashlib.sha256(f"{self.definition.workflow_id}:{self.started_at}".encode("utf-8")).hexdigest()[:16]
        self.workflow_status = _normalize_status(self.workflow_status, WORKFLOW_STATUSES, "pending")
        if not isinstance(self.variable_store, WorkflowVariableStore):
            self.variable_store = WorkflowVariableStore(**(self.variable_store or {}))
        if not isinstance(self.final_verdict, WorkflowVerdict):
            self.final_verdict = WorkflowVerdict(**(self.final_verdict or {}))
        self.finished_at = self.finished_at or self.started_at

    @property
    def workflow_id(self) -> str:
        return self.definition.workflow_id

    @property
    def title(self) -> str:
        return self.definition.title

    @property
    def actors(self) -> List[str]:
        return list(dict.fromkeys(self.definition.actors + [item.actor_id for item in self.step_results if item.actor_id]))

    def step_result_map(self) -> Dict[str, WorkflowStepResult]:
        return {result.step_id: result for result in self.step_results}

    def checkpoint_result_map(self) -> Dict[str, WorkflowCheckpointResult]:
        return {result.checkpoint_id: result for result in self.checkpoint_results}

    def to_summary(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "execution_id": self.execution_id,
            "title": self.title,
            "status": self.workflow_status,
            "actors": self.actors,
            "step_count": len(self.definition.steps),
            "completed_steps": len([item for item in self.step_results if item.status == "completed"]),
            "failed_steps": len([item for item in self.step_results if item.status == "failed"]),
            "blocked_auth_steps": len([item for item in self.step_results if item.status == "blocked_auth"]),
            "checkpoint_count": len(self.checkpoint_results),
            "verdict": asdict(self.final_verdict),
            "variables": self.variable_store.to_summary(),
            "artifact_refs": list(self.artifact_refs),
            "notes": list(self.notes),
            "errors": list(self.errors),
            "replay_records": [asdict(item) for item in self.replay_records],
        }


VerificationPoint = WorkflowCheckpoint
Workflow = WorkflowDefinition
