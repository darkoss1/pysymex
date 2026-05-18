"""Tests for runtime detector benchmark harness behavior."""

from __future__ import annotations

from tests.repro.detector_benchmark import (
    RUNTIME_CASES,
    format_report,
    run_runtime_detector_benchmark,
)


def test_runtime_detector_benchmark_executes_all_cases() -> None:
    """Verify benchmark execution returns one outcome per configured runtime case."""
    report = run_runtime_detector_benchmark()
    assert report.total_cases() == len(RUNTIME_CASES)


def test_runtime_detector_benchmark_score_count_matches_detector_count() -> None:
    """Verify one score row is produced for each unique detector in the benchmark cases."""
    report = run_runtime_detector_benchmark()
    unique_detectors = {case.detector_name for case in RUNTIME_CASES}
    assert len(report.scores) == len(unique_detectors)


def test_runtime_detector_benchmark_report_format_contains_total_cases() -> None:
    """Verify formatted report includes aggregate total case count for quick inspection."""
    report = run_runtime_detector_benchmark()
    rendered = format_report(report)
    assert "Total cases:" in rendered


def test_runtime_detector_benchmark_includes_path_explosion_cases() -> None:
    """Verify high-complexity path-explosion corpus cases are registered."""
    case_names = {case.function_name for case in RUNTIME_CASES}
    expected_cases = {
        "division_by_zero_path_explosion_positive",
        "division_by_zero_path_explosion_negative",
        "resource_leak_path_explosion_positive",
        "resource_leak_path_explosion_negative",
        "value_error_path_explosion_positive",
        "value_error_path_explosion_negative",
    }
    assert expected_cases.issubset(case_names)


def test_runtime_detector_benchmark_path_explosion_outcomes_match_expectations() -> None:
    """Verify path-explosion outcomes match expected labels for hard detector cases."""
    report = run_runtime_detector_benchmark()
    path_explosion_outcomes = {
        outcome.function_name: outcome.observed_detected
        for outcome in report.outcomes
        if "path_explosion" in outcome.function_name
    }
    assert path_explosion_outcomes == {
        "division_by_zero_path_explosion_positive": True,
        "division_by_zero_path_explosion_negative": False,
        "resource_leak_path_explosion_positive": True,
        "resource_leak_path_explosion_negative": False,
        "value_error_path_explosion_positive": True,
        "value_error_path_explosion_negative": False,
    }
