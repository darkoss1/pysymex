"""Scanner regressions for dictionary iterator key semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_next_dict_iterator_reports_zero_key_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_iterator_zero_key.py"
    target.write_text(
        "def target() -> int:\n    key = next(iter({0: 1}))\n    return 10 // key\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_dict_iterator_preserves_nonzero_key(tmp_path: Path) -> None:
    target = tmp_path / "dict_iterator_nonzero_key.py"
    target.write_text(
        "def target() -> int:\n    key = next(iter({1: 0}))\n    return 10 // key\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_empty_dict_iterator_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "dict_iterator_empty.py"
    target.write_text(
        "def target() -> object:\n    return next(iter({}))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_empty_dict_iterator_default_preserves_safe_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_iterator_empty_default_safe.py"
    target.write_text(
        "def target() -> int:\n    key = next(iter({}), 1)\n    return 10 // key\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_empty_dict_iterator_default_reports_zero_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_iterator_empty_default_bug.py"
    target.write_text(
        "def target() -> int:\n    key = next(iter({}), 0)\n    return 10 // key\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
