"""Scanner regressions for exact string and bytes split-family methods."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_str_partition_preserves_nonempty_head(tmp_path: Path) -> None:
    target = tmp_path / "str_partition_head.py"
    target.write_text(
        "def target() -> int:\n    part = 'a:b'.partition(':')[0]\n    return 10 // len(part)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_partition_reports_empty_head_division(tmp_path: Path) -> None:
    target = tmp_path / "str_partition_empty_head.py"
    target.write_text(
        "def target() -> int:\n    part = ':b'.partition(':')[0]\n    return 10 // len(part)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_partition_reports_empty_separator_value_error(tmp_path: Path) -> None:
    target = tmp_path / "str_partition_empty_separator.py"
    target.write_text(
        "def target() -> tuple[str, str, str]:\n    return 'a'.partition('')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_str_rpartition_preserves_nonempty_tail(tmp_path: Path) -> None:
    target = tmp_path / "str_rpartition_tail.py"
    target.write_text(
        "def target() -> int:\n    part = 'a:b'.rpartition(':')[2]\n    return 10 // len(part)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_splitlines_preserves_nonempty_head(tmp_path: Path) -> None:
    target = tmp_path / "str_splitlines_head.py"
    target.write_text(
        "def target() -> int:\n    line = 'a\\nb'.splitlines()[0]\n    return 10 // len(line)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_splitlines_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "str_splitlines_empty_index.py"
    target.write_text(
        "def target() -> str:\n    return ''.splitlines()[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_partition_preserves_nonempty_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_partition_head.py"
    target.write_text(
        "def target() -> int:\n    part = b'a:b'.partition(b':')[0]\n    return 10 // part[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_partition_reports_empty_separator_value_error(tmp_path: Path) -> None:
    target = tmp_path / "bytes_partition_empty_separator.py"
    target.write_text(
        "def target() -> tuple[bytes, bytes, bytes]:\n    return b'a'.partition(b'')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytes_rpartition_preserves_nonempty_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytes_rpartition_tail.py"
    target.write_text(
        "def target() -> int:\n    part = b'a:b'.rpartition(b':')[2]\n    return 10 // part[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_splitlines_preserves_nonempty_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_splitlines_head.py"
    target.write_text(
        "def target() -> int:\n    line = b'a\\nb'.splitlines()[0]\n    return 10 // line[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_splitlines_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_splitlines_empty_index.py"
    target.write_text(
        "def target() -> bytes:\n    return b''.splitlines()[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")
