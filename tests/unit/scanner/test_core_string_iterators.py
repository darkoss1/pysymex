"""Scanner regressions for string iterator character semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_next_empty_string_iterator_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "string_iterator_empty.py"
    target.write_text(
        "def target() -> object:\n    return next(iter(''))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_empty_string_iterator_default_preserves_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "string_iterator_empty_default_safe.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter(''), 1)\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_empty_string_iterator_default_reports_zero_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "string_iterator_empty_default_bug.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter(''), 0)\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_from_empty_string_iterator_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "string_iterator_list_empty.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(iter(''))\n"
        "    if values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_list_from_string_iterator_is_truthy(tmp_path: Path) -> None:
    target = tmp_path / "string_iterator_list_nonempty.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(iter('a'))\n"
        "    if not values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
