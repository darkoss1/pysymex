"""Scanner regressions for callable adapters that preserve symbolic values."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from pysymex.scanner.file import scan_file


def test_scan_file_reports_attrgetter_derived_division(tmp_path: Path) -> None:
    target = tmp_path / "attrgetter_helper_bug.py"
    target.write_text(
        "from operator import attrgetter\n\n"
        "class Payload:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value - 11\n\n"
        "def target(value: int) -> int:\n"
        "    getter = attrgetter('denominator')\n"
        "    denominator = getter(Payload(value))\n"
        "    return 10 // denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    issue = next(
        (
            issue
            for issue in result.issues
            if issue.get("kind") == "DIVISION_BY_ZERO"
            and issue.get("function_name") == "target"
            and issue.get("line") == 10
        ),
        None,
    )
    assert issue is not None
    counterexample_obj = issue.get("counterexample")
    assert isinstance(counterexample_obj, dict)
    counterexample = cast("dict[str, object]", counterexample_obj)
    assert counterexample.get("value") == 11


def test_scan_file_allows_guarded_attrgetter_derived_division(tmp_path: Path) -> None:
    target = tmp_path / "attrgetter_helper_safe.py"
    target.write_text(
        "from operator import attrgetter\n\n"
        "class Payload:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value - 11\n\n"
        "def target(value: int) -> int:\n"
        "    denominator = attrgetter('denominator')(Payload(value))\n"
        "    if denominator == 0:\n"
        "        return 0\n"
        "    return 10 // denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_itemgetter_symbolic_index_error(tmp_path: Path) -> None:
    target = tmp_path / "itemgetter_index_bug.py"
    target.write_text(
        "from operator import itemgetter\n\n"
        "def target(index: int) -> int:\n"
        "    getter = itemgetter(index)\n"
        "    return getter([3, 5, 8])\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    issue = next(
        (
            issue
            for issue in result.issues
            if issue.get("kind") == "INDEX_ERROR"
            and issue.get("function_name") == "target"
            and issue.get("line") == 5
        ),
        None,
    )

    assert issue is not None
    counterexample_obj = issue.get("counterexample")
    assert isinstance(counterexample_obj, dict)
    counterexample = cast("dict[str, object]", counterexample_obj)
    index = counterexample.get("index")
    assert isinstance(index, int)
    assert index < -3 or index >= 3


def test_scan_file_allows_guarded_itemgetter_symbolic_index(tmp_path: Path) -> None:
    target = tmp_path / "itemgetter_index_safe.py"
    target.write_text(
        "from operator import itemgetter\n\n"
        "def target(index: int) -> int:\n"
        "    if 0 <= index < 3:\n"
        "        getter = itemgetter(index)\n"
        "        return getter([3, 5, 8])\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_range_membership_guarded_symbolic_index(tmp_path: Path) -> None:
    target = tmp_path / "range_membership_index_safe.py"
    target.write_text(
        "def target(index: int) -> int:\n"
        "    values = [1, 2, 3]\n"
        "    if index in range(len(values)):\n"
        "        return values[index]\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_slice_indices_stop_at_list_length(tmp_path: Path) -> None:
    target = tmp_path / "slice_indices_bug.py"
    target.write_text(
        "def target(stop: int) -> int:\n"
        "    values = [2, 4, 6]\n"
        "    normalized = slice(None, stop).indices(len(values))\n"
        "    return values[normalized[1]]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    issue = next(
        (
            issue
            for issue in result.issues
            if issue.get("kind") == "INDEX_ERROR"
            and issue.get("function_name") == "target"
            and issue.get("line") == 4
        ),
        None,
    )
    assert issue is not None
    counterexample_obj = issue.get("counterexample")
    assert isinstance(counterexample_obj, dict)
    counterexample = cast("dict[str, object]", counterexample_obj)
    stop = counterexample.get("stop")
    assert isinstance(stop, int)
    assert stop >= 3
    assert not any(issue.get("kind") == "NULL_DEREFERENCE" for issue in result.issues)


def test_scan_file_allows_guarded_slice_indices_stop(tmp_path: Path) -> None:
    target = tmp_path / "slice_indices_safe.py"
    target.write_text(
        "def target(stop: int) -> int:\n"
        "    values = [2, 4, 6]\n"
        "    normalized = slice(None, stop).indices(len(values))\n"
        "    index = normalized[1]\n"
        "    if index >= len(values):\n"
        "        return 0\n"
        "    return values[index]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"INDEX_ERROR", "NULL_DEREFERENCE"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_bitwise_guarded_symbolic_index_error(tmp_path: Path) -> None:
    target = tmp_path / "bitwise_guarded_index_bug.py"
    target.write_text(
        "def target(a: int, b: int, c: int, d: int, e: int, f: int) -> int:\n"
        "    values = [a, b, c]\n"
        "    index = (a ^ d) + (b & 3) + (e - f)\n"
        "    if ((a + c) == (d - f)) and ((b ^ e) & 3) == 2:\n"
        "        return values[index]\n"
        "    return values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=40)

    issue = next(
        (
            issue
            for issue in result.issues
            if issue.get("kind") == "INDEX_ERROR"
            and issue.get("function_name") == "target"
            and issue.get("line") == 5
        ),
        None,
    )
    assert issue is not None
    assert "solver_unknown_detector_query" not in result.degraded_passes


def test_scan_file_allows_guarded_bitwise_symbolic_index(tmp_path: Path) -> None:
    target = tmp_path / "bitwise_guarded_index_safe.py"
    target.write_text(
        "def target(a: int, b: int, c: int, d: int, e: int, f: int) -> int:\n"
        "    values = [a, b, c]\n"
        "    index = (a ^ d) + (b & 3) + (e - f)\n"
        "    if ((a + c) == (d - f)) and ((b ^ e) & 3) == 2:\n"
        "        if -len(values) <= index < len(values):\n"
        "            return values[index]\n"
        "    return values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=40)

    assert not any(
        issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
