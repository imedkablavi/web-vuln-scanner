from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from typing import Any, Dict, List

from .models import ArtifactReference


class ArtifactStore:
    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        self._artifacts: List[ArtifactReference] = []

    def _artifact_id(
        self,
        kind: str,
        path: str,
        actor_id: str = "",
        finding_id: str = "",
        workflow_id: str = "",
        execution_id: str = "",
        step_id: str = "",
        checkpoint_id: str = "",
        replay_id: str = "",
    ) -> str:
        seed = f"{kind}:{os.path.abspath(path)}:{actor_id}:{finding_id}:{workflow_id}:{execution_id}:{step_id}:{checkpoint_id}:{replay_id}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    def register_file(
        self,
        kind: str,
        path: str,
        *,
        actor_id: str = "",
        finding_id: str = "",
        workflow_id: str = "",
        execution_id: str = "",
        step_id: str = "",
        checkpoint_id: str = "",
        replay_id: str = "",
        artifact_role: str = "",
        description: str = "",
        metadata: Dict[str, Any] | None = None,
    ) -> ArtifactReference:
        reference = ArtifactReference(
            artifact_id=self._artifact_id(
                kind,
                path,
                actor_id=actor_id,
                finding_id=finding_id,
                workflow_id=workflow_id,
                execution_id=execution_id,
                step_id=step_id,
                checkpoint_id=checkpoint_id,
                replay_id=replay_id,
            ),
            kind=kind,
            path=os.path.abspath(path),
            actor_id=actor_id,
            finding_id=finding_id,
            workflow_id=workflow_id,
            execution_id=execution_id,
            step_id=step_id,
            checkpoint_id=checkpoint_id,
            replay_id=replay_id,
            artifact_role=artifact_role,
            description=description,
            metadata=dict(metadata or {}),
        )
        self._artifacts.append(reference)
        return reference

    def write_json(
        self,
        kind: str,
        name: str,
        payload: Dict[str, Any],
        *,
        actor_id: str = "",
        finding_id: str = "",
        workflow_id: str = "",
        execution_id: str = "",
        step_id: str = "",
        checkpoint_id: str = "",
        replay_id: str = "",
        artifact_role: str = "",
        description: str = "",
    ) -> ArtifactReference:
        directory = os.path.join(self.base_dir, kind)
        os.makedirs(directory, exist_ok=True)
        safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in name).strip("-") or kind
        path = os.path.join(directory, f"{safe_name}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return self.register_file(
            kind,
            path,
            actor_id=actor_id,
            finding_id=finding_id,
            workflow_id=workflow_id,
            execution_id=execution_id,
            step_id=step_id,
            checkpoint_id=checkpoint_id,
            replay_id=replay_id,
            artifact_role=artifact_role,
            description=description,
            metadata={"format": "json"},
        )

    def index(self) -> List[Dict[str, Any]]:
        return [asdict(reference) for reference in self._artifacts]
