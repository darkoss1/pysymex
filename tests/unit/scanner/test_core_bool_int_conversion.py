"""Scanner regressions for bool/int conversion precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.config import is_object_dict
from pysymex.scanner.types import IssueRecord
from pysymex.scanner.file import scan_file


def _counterexample_limit(issue: IssueRecord) -> object:
    counterexample = issue.get("counterexample")
    if not is_object_dict(counterexample):
        return None
    return counterexample.get("limit")


def test_scan_file_does_not_treat_bool_int_conversion_as_invalid_string(
    tmp_path: Path,
) -> None:
    """int(False) is valid CPython behavior and must not report ValueError."""
    target = tmp_path / "bool_int_conversion.py"
    target.write_text(
        "def target(flag: bool) -> int:\n"
        "    value = False\n"
        "    if flag:\n"
        "        value = True\n"
        "    return int(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_preserves_nonlocal_zero_int_mutation_through_helper(
    tmp_path: Path,
) -> None:
    """A nested helper mutating nonlocal count should update the later divisor."""
    target = tmp_path / "nonlocal_count.py"
    target.write_text(
        "def target(limit: int) -> int:\n"
        "    count = 0\n"
        "    def bump() -> None:\n"
        "        nonlocal count\n"
        "        count += 1\n"
        "    bump()\n"
        "    return 10 // (count - limit)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    matching = [
        issue
        for issue in result.issues
        if issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
    ]

    assert any(_counterexample_limit(issue) == 1 for issue in matching)
    assert not any(_counterexample_limit(issue) == 0 for issue in matching)
