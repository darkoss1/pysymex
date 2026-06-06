"""Failure-state coverage for CI SARIF reports."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pysymex.ci.runner import CIRunner, run_ci_check
from pysymex.scanner.types import ScanResult


def test_ci_sarif_records_analysis_errors_as_failed_execution(tmp_path: Path) -> None:
    output_path = tmp_path / "report.sarif"
    runner = CIRunner(sarif_output=str(output_path))

    runner.analyze_and_report(
        files=["failed.py"],
        vulnerabilities=[],
        issues=[
            {
                "type": "analysis_error",
                "severity": "high",
                "file": "failed.py",
                "message": "unsupported construct",
            }
        ],
    )

    report = json.loads(output_path.read_text(encoding="utf-8"))
    invocation = report["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["analysisErrors"] == ["unsupported construct"]


def test_ci_sarif_records_degraded_scan_as_failed_execution(tmp_path: Path) -> None:
    target = tmp_path / "degraded.py"
    target.write_text("x = 1\n", encoding="utf-8")
    output_path = tmp_path / "report.sarif"
    result = ScanResult(
        file_path=str(target),
        timestamp="now",
        degraded_passes=["solver_unknown_detector_query"],
    )

    with patch("pysymex.scanner.scan_file", return_value=result):
        exit_code = run_ci_check([str(target)], sarif_output=str(output_path))

    report = json.loads(output_path.read_text(encoding="utf-8"))
    invocation = report["runs"][0]["invocations"][0]
    assert exit_code != 0
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["analysisErrors"] == [
        "Analysis degraded: solver_unknown_detector_query"
    ]
