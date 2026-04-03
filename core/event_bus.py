from __future__ import annotations

import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import ScanEvent


class EventBus:
    def __init__(self):
        self._events: List[ScanEvent] = []

    def emit(self, kind: str, payload: Dict[str, Any]) -> ScanEvent:
        timestamp = datetime.now(timezone.utc).isoformat()
        seed = f"{kind}:{timestamp}:{len(self._events)}:{payload.get('fingerprint', '')}"
        event = ScanEvent(
            event_id=hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16],
            kind=str(kind or "unknown"),
            timestamp=timestamp,
            payload=dict(payload or {}),
        )
        self._events.append(event)
        return event

    def emit_record(self, kind: str, record) -> ScanEvent:
        return self.emit(kind, asdict(record) if hasattr(record, "__dataclass_fields__") else dict(record or {}))

    def get_events(self, kind: str | None = None) -> List[ScanEvent]:
        if kind is None:
            return list(self._events)
        return [event for event in self._events if event.kind == kind]

    def summary(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for event in self._events:
            by_kind[event.kind] = by_kind.get(event.kind, 0) + 1
        return {"total_events": len(self._events), "by_kind": by_kind}
