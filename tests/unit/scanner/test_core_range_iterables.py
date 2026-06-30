"""Scanner regressions for exact range() iterable behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_range_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "list_range_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(range(1, 2))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_range_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_range_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(range(1))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_empty_list_range_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "list_range_empty_falsy.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(range(0))\n"
        "    if values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_empty_range_truthiness_reports_negated_branch(tmp_path: Path) -> None:
    target = tmp_path / "range_empty_truthiness.py"
    target.write_text(
        "def target() -> int:\n    if not range(0):\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_second_next_on_range_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "range_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = iter(range(1))\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_range_default_suppresses_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "range_next_default.py"
    target.write_text(
        "def target() -> int:\n"
        "    iterator = iter(range(1))\n"
        "    next(iterator)\n"
        "    return next(iterator, 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_range_float_argument_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "range_float_type_error.py"
    target.write_text(
        "def target() -> object:\n    return range(1.0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_range_zero_step_reports_value_error(tmp_path: Path) -> None:
    target = tmp_path / "range_zero_step.py"
    target.write_text(
        "def target() -> object:\n    return range(1, 4, 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")
