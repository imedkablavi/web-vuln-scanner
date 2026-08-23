from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from core.models import Finding


_ENGINE_PATTERNS = {
    "Python": [
        re.compile(r"traceback \(most recent call last\)", re.I),
        re.compile(r"file \"[^\"]+\", line \d+", re.I),
    ],
    "PHP": [
        re.compile(r"(?:fatal error|uncaught [^:]+):", re.I),
        re.compile(r"stack trace:", re.I),
        re.compile(r" in /[^\n]+ on line \d+", re.I),
    ],
    "Java": [
        re.compile(r"(?:java|javax)\.[a-z0-9_.]+(?:exception|error)", re.I),
        re.compile(r"\bat [a-z0-9_.$]+\([^\n]+\.java:\d+\)", re.I),
    ],
    ".NET": [
        re.compile(r"server error in ['\"]/.*?['\"] application", re.I),
        re.compile(r"\bsystem\.[a-z0-9_.]+exception\b", re.I),
        re.compile(r"\bat [a-z0-9_.]+\([^\n]*\)", re.I),
    ],
    "Node.js": [
        re.compile(r"\b(?:error|typeerror|referenceerror):[^\n]*", re.I),
        re.compile(r"\bat [^\n]*\([^\n]+\.m?js:\d+:\d+\)", re.I),
    ],
    "Ruby": [
        re.compile(r"\.rb:\d+:in [`'][^`']+[`']", re.I),
        re.compile(r"from [^\n]+\.rb:\d+", re.I),
    ],
    "Go": [
        re.compile(r"goroutine \d+ \[[^\]]+\]", re.I),
        re.compile(r"[^\s]+\.go:\d+", re.I),
    ],
}


def detect_stack_trace(snapshot: Dict[str, Any]) -> List[Finding]:
    """Detect high-confidence stack traces without copying target content."""

    body = str(snapshot.get("text") or "")
    if not body:
        return []
    sample = body[:1_000_000]
    detected: List[Dict[str, Any]] = []

    for engine, patterns in _ENGINE_PATTERNS.items():
        matched = [index for index, pattern in enumerate(patterns) if pattern.search(sample)]
        # A single highly specific Python/Go/Ruby marker is sufficient. Other
        # runtimes require two signals to avoid matching ordinary page text.
        minimum = 1 if engine in {"Python", "Ruby", "Go"} else 2
        if len(matched) >= minimum:
            detected.append({"engine": engine, "signals": len(matched)})

    if not detected:
        return []

    digest = hashlib.sha256(sample.encode("utf-8", errors="replace")).hexdigest()[:16]
    return [
        Finding(
            plugin="web_posture",
            type="Stack Trace Disclosure",
            title="Application Response Exposes a Runtime Stack Trace",
            category="information-disclosure",
            severity="MEDIUM",
            confidence="HIGH",
            surface_id=f"stacktrace:{snapshot['url']}",
            url=snapshot["url"],
            evidence={
                "status": snapshot.get("status"),
                "detected_runtimes": detected,
                "response_body_sha256_prefix": digest,
                "response_length": len(body),
            },
            remediation="Return generic client errors and keep stack traces and runtime diagnostics in restricted server-side logs.",
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
    ]
