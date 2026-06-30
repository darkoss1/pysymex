"""Scanner regressions for concrete bounded loop execution."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.analysis.records import IssueRecord
from pysymex._internal.config.values import ConfigValues
from pysymex._internal.scanner.file import scan_file


def _counterexample_limit(issue: IssueRecord) -> object:
    counterexample = issue.get("counterexample")
    if not ConfigValues.is_object_dict(counterexample):
        return None
    return counterexample.get("limit")


def test_scan_file_detects_concrete_range_accumulator_division(tmp_path: Path) -> None:
    """range(10) should accumulate to 45 and expose limit == 45."""
    target = tmp_path / "range_accumulator_bug.py"
    target.write_text(
        "def target(limit: int) -> int:\n"
        "    accumulated = 0\n"
        "    for i in range(10):\n"
        "        accumulated += i\n"
        "    return 45 // (accumulated - limit)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        and _counterexample_limit(issue) == 45
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "UNKNOWN" for issue in result.issues)


def test_scan_file_does_not_report_guarded_concrete_range_accumulator(
    tmp_path: Path,
) -> None:
    """A guard against the concrete accumulated value should prevent a false bug."""
    target = tmp_path / "range_accumulator_safe.py"
    target.write_text(
        "def target(limit: int) -> int:\n"
        "    accumulated = 0\n"
        "    for i in range(3, 12, 2):\n"
        "        accumulated += i\n"
        "    if limit == accumulated:\n"
        "        return 0\n"
        "    return 45 // (accumulated - limit)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "UNKNOWN" for issue in result.issues)


def test_scan_file_detects_zero_at_start_of_bounded_range_eleven(tmp_path: Path) -> None:
    """A bounded range beyond loop unrolling still preserves its first zero item."""
    target = tmp_path / "range_eleven_first_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    for value in range(11):\n"
        "        result = 1 // value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_does_not_report_nonzero_bounded_range_eleven(tmp_path: Path) -> None:
    """A bounded nonzero range must not create a synthetic division finding."""
    target = tmp_path / "range_eleven_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    for value in range(1, 12):\n"
        "        result = 1 // value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_preserves_concrete_zip_tuple_values(tmp_path: Path) -> None:
    """Finite zip tuple unpacking should not create a false type finding."""
    target = tmp_path / "zip_shortest_safe.py"
    target.write_text(
        "def target(i: int) -> int:\n"
        "    pairs = list(zip([1, 2, 3], [4]))\n"
        "    if 0 <= i < len(pairs):\n"
        "        left, right = pairs[i]\n"
        "        return left + right\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("function_name") == "target"
        and issue.get("kind") in {"TYPE_ERROR", "INDEX_ERROR"}
        for issue in result.issues
    )


def test_scan_file_uses_concrete_zip_shortest_length_for_bad_index(tmp_path: Path) -> None:
    """An index beyond the shorter zipped input should remain reportable."""
    target = tmp_path / "zip_shortest_bug.py"
    target.write_text(
        "def target(i: int) -> int:\n"
        "    pairs = list(zip([1, 2, 3], [4]))\n"
        "    if i == 1:\n"
        "        left, right = pairs[i]\n"
        "        return left + right\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("function_name") == "target"
        and issue.get("kind") == "INDEX_ERROR"
        and issue.get("line") == 4
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") == "TYPE_ERROR"
        for issue in result.issues
    )
