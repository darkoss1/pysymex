"""Scanner regressions for exact reversed() iterator behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_reversed_bytes_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "reversed_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(reversed(b'\\x01'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_reversed_bytes_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "reversed_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(reversed(b'\\x00'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_reversed_string_truthiness_is_exact(tmp_path: Path) -> None:
    target = tmp_path / "reversed_string_truthy.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(reversed('a'))\n"
        "    if not values[0]:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_second_next_on_reversed_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "reversed_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = reversed([1])\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_reversed_set_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "reversed_set.py"
    target.write_text(
        "def target() -> object:\n    return reversed({1})\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
