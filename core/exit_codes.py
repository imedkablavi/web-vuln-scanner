from __future__ import annotations


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_FAILED = 2
EXIT_PARTIAL_OR_ABORTED = 3


def scan_exit_code(status: str, finding_count: int) -> int:
    """Return the documented process exit code for a completed scan result."""
    normalized = str(status or "completed").strip().lower()
    if normalized == "failed":
        return EXIT_FAILED
    if normalized in {"partial", "aborted", "cancelled", "canceled"}:
        return EXIT_PARTIAL_OR_ABORTED
    if int(finding_count or 0) > 0:
        return EXIT_FINDINGS
    return EXIT_OK
