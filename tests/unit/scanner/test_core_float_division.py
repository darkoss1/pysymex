"""Tests for symbolic float division diagnostics."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_feasible_symbolic_float_division_by_zero(
    tmp_path: Path,
) -> None:
    target = tmp_path / "float_division_bug.py"
    target.write_text(
        "def target(x: float) -> float:\n    if x <= 0.0:\n        x = 0.0\n    return 4.0 / x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_float_multiplication_zero_witness(tmp_path: Path) -> None:
    target = tmp_path / "float_expression_division_bug.py"
    target.write_text(
        "def target(x: float) -> float:\n    denominator = x * x\n    return 1.0 / denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )
    assert "solver_unknown_detector_query" not in result.degraded_passes


def test_scan_file_does_not_report_guarded_symbolic_float_division(
    tmp_path: Path,
) -> None:
    target = tmp_path / "float_division_guarded.py"
    target.write_text(
        "def target(x: float, flag: bool) -> float:\n"
        "    denom = 0.0 if flag else x\n"
        "    if denom == 0.0:\n"
        "        denom = 2.0\n"
        "    return 1.5 / denom\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_uses_float_truthiness_to_guard_zero_division(tmp_path: Path) -> None:
    target = tmp_path / "float_truthiness_guarded.py"
    target.write_text(
        "def target(x: float) -> float:\n    if not x:\n        return 0.0\n    return 3.5 / x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
