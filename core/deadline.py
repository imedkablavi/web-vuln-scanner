from __future__ import annotations

import os
import time
from dataclasses import dataclass


DEADLINE_ENV = "WEBVULN_SCAN_DEADLINE_MONOTONIC"


@dataclass(frozen=True)
class ScanDeadline:
    deadline_monotonic: float

    @classmethod
    def from_config(cls, config: dict) -> "ScanDeadline":
        raw = os.getenv(DEADLINE_ENV, "").strip()
        if raw:
            try:
                return cls(float(raw))
            except ValueError:
                pass
        seconds = float(
            config.get("concurrency", {}).get("global_timeout_seconds", 600) or 600
        )
        return cls(time.monotonic() + max(1.0, seconds))

    def remaining(self) -> float:
        return max(0.0, self.deadline_monotonic - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def require(self) -> None:
        if self.expired():
            raise TimeoutError("Global scan deadline exceeded")


def install_deadline(config: dict) -> ScanDeadline:
    """Install a fresh process deadline for one top-level scan invocation."""
    seconds = float(
        config.get("concurrency", {}).get("global_timeout_seconds", 600) or 600
    )
    deadline = ScanDeadline(time.monotonic() + max(1.0, seconds))
    os.environ[DEADLINE_ENV] = str(deadline.deadline_monotonic)
    return deadline
