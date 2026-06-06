"""Scanner regressions for bytes iterator integer-item semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_next_bytes_iterator_reports_zero_byte_bug(tmp_path: Path) -> None:
    target = tmp_path / "bytes_iterator_zero.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter(b'\\x00'))\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_bytes_iterator_preserves_nonzero_byte(tmp_path: Path) -> None:
    target = tmp_path / "bytes_iterator_nonzero.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter(b'\\x01'))\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_from_bytes_iterator_reports_zero_byte_bug(tmp_path: Path) -> None:
    target = tmp_path / "bytes_iterator_list_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(iter(b'\\x00'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_from_bytes_iterator_preserves_nonzero_byte(tmp_path: Path) -> None:
    target = tmp_path / "bytes_iterator_list_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(iter(b'\\x01'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_empty_bytes_iterator_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "bytes_iterator_empty.py"
    target.write_text(
        "def target() -> object:\n    return next(iter(b''))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_empty_bytes_iterator_default_preserves_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytes_iterator_empty_default.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter(b''), 1)\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
