"""Scanner regressions for bytearray split and search methods."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytearray_split_preserves_nonzero_element(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_split_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    parts = bytearray(b'A,B').split(b',')\n"
        "    return 10 // parts[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_split_reports_zero_element(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_split_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    parts = bytearray(b'\\x00,A').split(b',')\n"
        "    return 10 // parts[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_split_empty_separator_reports_value_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytearray_split_empty_separator.py"
    target.write_text(
        "def target() -> int:\n    return len(bytearray(b'A').split(b''))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytearray_partition_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_partition_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    head, _sep, _tail = bytearray(b'A:B').partition(b':')\n"
        "    return 10 // head[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_partition_empty_separator_reports_value_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytearray_partition_empty_separator.py"
    target.write_text(
        "def target() -> int:\n    return len(bytearray(b'A').partition(b''))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytearray_splitlines_preserves_nonzero_element(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_splitlines_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    lines = bytearray(b'A\\nB').splitlines()\n"
        "    return 10 // lines[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_startswith_false_skips_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_startswith_false.py"
    target.write_text(
        "def target() -> int:\n"
        "    if bytearray(b'A').startswith(b'Z'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_index_missing_reports_value_error(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_index_missing.py"
    target.write_text(
        "def target() -> int:\n    return bytearray(b'A').index(b'Z')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")
