"""Scanner regressions for builtin sum() symbolic relations."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_respects_symbolic_sum_relation_guard(tmp_path: Path) -> None:
    target = tmp_path / "sum_relation_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    total = sum([x, 1])\n"
        "    if total == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_symbolic_sum_zero_relation_bug(tmp_path: Path) -> None:
    target = tmp_path / "sum_relation_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    total = sum([x, 1])\n"
        "    if total == 1:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_sum_generator_expression_division(tmp_path: Path) -> None:
    target = tmp_path / "sum_generator_division.py"
    target.write_text(
        "def target(y: int) -> object:\n    result = sum(10 // item for item in [y])\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_respects_sum_generator_expression_nonzero_filter(tmp_path: Path) -> None:
    target = tmp_path / "sum_generator_filter_guard.py"
    target.write_text(
        "def target(y: int) -> object:\n"
        "    result = sum(10 // item for item in [y] if item != 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
