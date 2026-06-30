"""Tests for pure scan summary helpers."""

from __future__ import annotations

from pysymex._internal.reporting.summary import summarize_scan_results
from pysymex._internal.scanner.types import ScanResult


def test_summarize_scan_results_counts_issue_error_and_degraded_files() -> None:
    """Summary helper computes counters without owning console presentation."""
    clean = ScanResult(file_path="clean.py", timestamp="now")
    issue = ScanResult(file_path="issue.py", timestamp="now")
    issue.issues.append({"kind": "DIVISION_BY_ZERO"})
    errored = ScanResult(file_path="error.py", timestamp="now", error="failed")
    degraded = ScanResult(file_path="degraded.py", timestamp="now")
    degraded.degraded_passes.append("solver_unknown")

    summary = summarize_scan_results([clean, issue, errored, degraded], total_files=5)

    assert summary.total_issues == 1
    assert summary.files_with_issues == 1
    assert summary.errors == 1
    assert summary.degraded == 1
    assert summary.missing_files == 1
