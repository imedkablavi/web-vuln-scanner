from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import fields
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit, urlunsplit

from .models import AttackSurface, Finding
from .redaction import redact_structure, redact_text


SCHEMA = "web-vuln-scanner-active-checkpoint/v1"
_ALLOWED_RESUME_STATUSES = {"in_progress", "partial", "aborted"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scanner_version() -> str:
    try:
        return version("web-vuln-scanner")
    except PackageNotFoundError:
        return "0.4.0-dev"


def _canonical_target(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("checkpoint target must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("checkpoint target must not contain URL credentials")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("checkpoint target contains an invalid port") from exc
    netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    canonical = urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )
    return redact_text(canonical)


def checkpoint_config_fingerprint(scanner_config: Dict[str, Any]) -> str:
    """Hash only active-scan semantics, after secret redaction.

    Output/report paths and the checkpoint settings themselves are intentionally
    excluded so a resumed run can write results somewhere else without being
    treated as a different scan definition.
    """

    keys = (
        "plugin_contract",
        "verified_only",
        "max_findings_per_plugin",
        "attack_policy",
        "plugins",
        "auth",
        "auth_verification",
        "rbac_matrix",
        "rbac_matrix_file",
    )
    selected = {key: scanner_config.get(key) for key in keys if key in scanner_config}
    safe = redact_structure(selected)
    raw = json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def testcase_fingerprint(plugin_name: str, surface: AttackSurface, testcase: Any) -> str:
    """Return a non-reversible identity for one concrete active testcase."""

    identity = {
        "plugin": str(plugin_name or "").strip().lower(),
        "surface_id": str(surface.id),
        "param": str(getattr(testcase, "param", "") or ""),
        "kind": str(getattr(testcase, "kind", "") or "").strip().lower(),
        "payload": str(getattr(testcase, "payload", "") or ""),
        "method_override": str(getattr(testcase, "method_override", "") or "").upper(),
        "allow_redirects": getattr(testcase, "allow_redirects", None),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _finding_init_fields() -> List[str]:
    return [item.name for item in fields(Finding) if item.init]


def _serialize_finding(finding: Finding) -> Dict[str, Any]:
    data = {name: getattr(finding, name) for name in _finding_init_fields()}
    return {
        "finding_fingerprint": finding.fingerprint,
        "data": redact_structure(data),
    }


def _deserialize_finding(record: Dict[str, Any]) -> Finding:
    raw = record.get("data") or {}
    if not isinstance(raw, dict):
        raise ValueError("checkpoint finding data must be an object")
    allowed = set(_finding_init_fields())
    finding = Finding(**{key: value for key, value in raw.items() if key in allowed})
    stored_fingerprint = str(record.get("finding_fingerprint", "") or "").strip()
    if stored_fingerprint:
        finding.fingerprint = stored_fingerprint
        finding.id = stored_fingerprint
    return finding


class ScanCheckpoint:
    """Thread-safe, secret-minimized resume ledger for V2 active plugin tests."""

    def __init__(
        self,
        path: str | Path,
        *,
        target: str,
        profile: str,
        scanner_config: Dict[str, Any],
        resume: bool = False,
        flush_every: int = 10,
        keep_completed: bool = False,
    ):
        self.path = Path(path)
        self.target = _canonical_target(target)
        self.profile = str(profile or "custom").strip().lower()
        self.config_fingerprint = checkpoint_config_fingerprint(scanner_config)
        self.scanner_version = _scanner_version()
        self.flush_every = max(1, int(flush_every or 1))
        self.keep_completed = bool(keep_completed)
        self.resume = bool(resume)
        self._lock = threading.Lock()
        self._dirty = 0
        self._created_at = _now()
        self._completed: set[str] = set()
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._status = "in_progress"

        if self.resume:
            self._load()
        else:
            self._flush_locked()

    @classmethod
    def from_scanner_config(cls, scanner_config: Dict[str, Any]) -> "ScanCheckpoint | None":
        cfg = scanner_config.get("checkpoint", {}) or {}
        if not isinstance(cfg, dict) or not cfg.get("enabled", False):
            return None
        path = str(cfg.get("path", "") or "").strip()
        if not path:
            raise ValueError("scanner.checkpoint.path is required when checkpointing is enabled")
        return cls(
            path,
            target=str(scanner_config.get("target", "") or ""),
            profile=str(scanner_config.get("profile", "custom") or "custom"),
            scanner_config=scanner_config,
            resume=bool(cfg.get("resume", False)),
            flush_every=int(cfg.get("flush_every", 10) or 10),
            keep_completed=bool(cfg.get("keep_completed", False)),
        )

    def _load(self) -> None:
        if not self.path.exists():
            raise ValueError(f"checkpoint file not found: {self.path}")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"unable to read checkpoint {self.path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise ValueError("checkpoint schema is unsupported or invalid")
        if str(data.get("target", "")) != self.target:
            raise ValueError("checkpoint target does not match the requested target")
        if str(data.get("profile", "")).strip().lower() != self.profile:
            raise ValueError("checkpoint profile does not match the requested profile")
        if str(data.get("config_fingerprint", "")) != self.config_fingerprint:
            raise ValueError("checkpoint active-scan configuration does not match")
        status = str(data.get("status", "") or "").strip().lower()
        if status not in _ALLOWED_RESUME_STATUSES:
            raise ValueError(
                "checkpoint is not resumable; only interrupted, partial, or in-progress checkpoints may be resumed"
            )
        completed = data.get("completed_testcases", []) or []
        if not isinstance(completed, list) or not all(isinstance(item, str) for item in completed):
            raise ValueError("checkpoint completed_testcases must be a list of hashes")
        findings = data.get("findings", []) or []
        if not isinstance(findings, list):
            raise ValueError("checkpoint findings must be a list")

        self._created_at = str(data.get("created_at", "") or _now())
        self._completed = set(completed)
        self._findings = {}
        for record in findings:
            if not isinstance(record, dict):
                continue
            fingerprint = str(record.get("finding_fingerprint", "") or "").strip()
            if fingerprint:
                # Validate that the sanitized record can still construct a Finding.
                _deserialize_finding(record)
                self._findings[fingerprint] = record
        self._status = "in_progress"
        self._dirty = 0
        self._flush_locked()

    def _document(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status": self._status,
            "target": self.target,
            "profile": self.profile,
            "scanner_version": self.scanner_version,
            "config_fingerprint": self.config_fingerprint,
            "created_at": self._created_at,
            "updated_at": _now(),
            "completed_testcases": sorted(self._completed),
            "findings": list(self._findings.values()),
            "summary": {
                "completed_testcases": len(self._completed),
                "findings": len(self._findings),
                "secret_minimized": True,
            },
        }

    def _flush_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        payload = json.dumps(self._document(), indent=2, ensure_ascii=False) + "\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        self._dirty = 0

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def is_completed(self, key: str) -> bool:
        with self._lock:
            return key in self._completed

    def restored_findings(self) -> List[Finding]:
        with self._lock:
            records = list(self._findings.values())
        return [_deserialize_finding(record) for record in records]

    def record_completed(self, key: str, finding: Finding | None = None) -> None:
        if not key:
            return
        with self._lock:
            self._completed.add(key)
            if finding is not None:
                record = _serialize_finding(finding)
                self._findings[finding.fingerprint] = record
            self._dirty += 1
            if self._dirty >= self.flush_every:
                self._flush_locked()

    def finalize(self, *, completed: bool) -> None:
        with self._lock:
            self._status = "completed" if completed else "partial"
            self._flush_locked()
            if completed and not self.keep_completed:
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": True,
                "resume": self.resume,
                "path": str(self.path),
                "status": self._status,
                "completed_testcases": len(self._completed),
                "restored_findings": len(self._findings),
                "flush_every": self.flush_every,
                "keep_completed": self.keep_completed,
                "secret_minimized": True,
            }


def count_findings_by_plugin(findings: Iterable[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.plugin] = counts.get(finding.plugin, 0) + 1
    return counts
