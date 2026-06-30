from __future__ import annotations

from pathlib import Path

import pytest

from pysymex._internal.profiling.comparison import ProfileBaselineError, compare_profile_report
from pysymex._internal.profiling.model import ProfileConfiguration, ScanProfileReport
from pysymex._internal.profiling.rendering import ScanProfileReports
from pysymex._internal.scanner.types import ScanResult


def test_profile_comparison_classifies_directional_metric_changes(tmp_path: Path) -> None:
    configuration = ProfileConfiguration(
        target_path="target.py",
        workers=1,
        max_paths=100,
        max_depth=50,
        timeout_seconds=10,
        max_iterations=0,
        cache_enabled=True,
        sandbox_enabled=True,
        trace_verbosity="delta_only",
    )
    baseline = ScanProfileReport.from_scan_results(
        [
            ScanResult(
                file_path="target.py",
                timestamp="before",
                paths_explored=10,
                elapsed_time=2.0,
                avg_memory_mb=100.0,
                solver_stats={"z3_check_calls": 10, "solver_time_ms": 100.0},
            )
        ],
        trace_output_dir="traces",
        configuration=configuration,
    )
    baseline_path = ScanProfileReports.write_summary(baseline, tmp_path)
    current = ScanProfileReport.from_scan_results(
        [
            ScanResult(
                file_path="target.py",
                timestamp="after",
                paths_explored=10,
                elapsed_time=1.0,
                avg_memory_mb=80.0,
                solver_stats={"z3_check_calls": 5, "solver_time_ms": 25.0},
            )
        ],
        trace_output_dir="traces",
        configuration=configuration,
    )

    comparison = compare_profile_report(current, baseline_path)
    statuses = {item.metric: item.status for item in comparison.metrics}

    assert comparison.compatible is True
    assert statuses["scan_elapsed_seconds"] == "improved"
    assert statuses["path_rate"] == "improved"
    assert statuses["paths_explored"] == "stable"
    assert statuses["solver_calls_per_path"] == "improved"
    assert statuses["max_memory_mb"] == "improved"


def test_profile_comparison_marks_configuration_drift(tmp_path: Path) -> None:
    baseline = ScanProfileReport.from_scan_results(
        [ScanResult(file_path="one.py", timestamp="before", elapsed_time=1.0)],
        trace_output_dir="traces",
    )
    baseline_path = ScanProfileReports.write_summary(baseline, tmp_path)
    current = ScanProfileReport.from_scan_results(
        [ScanResult(file_path="two.py", timestamp="after", elapsed_time=1.0)],
        trace_output_dir="traces",
    )

    comparison = compare_profile_report(current, baseline_path)

    assert comparison.compatible is False
    assert "configuration metadata is missing" in comparison.notes[0]


def test_profile_comparison_rejects_invalid_json(tmp_path: Path) -> None:
    baseline_path = tmp_path / "invalid.json"
    baseline_path.write_text("not-json", encoding="utf-8")
    report = ScanProfileReport.from_scan_results([], trace_output_dir="traces")

    with pytest.raises(ProfileBaselineError, match="invalid profile baseline JSON"):
        compare_profile_report(report, baseline_path)
