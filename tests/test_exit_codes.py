from core.exit_codes import (
    EXIT_FAILED,
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_PARTIAL_OR_ABORTED,
    scan_exit_code,
)


def test_clean_completed_scan_exits_zero():
    assert scan_exit_code("completed", 0) == EXIT_OK


def test_findings_exit_one():
    assert scan_exit_code("completed", 1) == EXIT_FINDINGS
    assert scan_exit_code("completed", 25) == EXIT_FINDINGS


def test_failed_scan_always_exits_two_even_without_findings():
    assert scan_exit_code("failed", 0) == EXIT_FAILED
    assert scan_exit_code("failed", 10) == EXIT_FAILED


def test_partial_and_aborted_scan_exit_three():
    assert scan_exit_code("partial", 0) == EXIT_PARTIAL_OR_ABORTED
    assert scan_exit_code("aborted", 3) == EXIT_PARTIAL_OR_ABORTED
