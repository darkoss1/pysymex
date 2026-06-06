"""Scanner regressions for exact string and bytes formatting methods."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytes_zfill_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_zfill_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x01'.zfill(2)\n    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_ljust_preserves_nonzero_prefix(tmp_path: Path) -> None:
    target = tmp_path / "bytes_ljust_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x01'.ljust(2, b'\\x00')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_center_has_nonempty_exact_length(tmp_path: Path) -> None:
    target = tmp_path / "bytes_center_nonempty.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'a'.center(3, b'x')\n"
        "    if len(data) == 0:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_center_reports_empty_fill_type_error(tmp_path: Path) -> None:
    target = tmp_path / "str_center_empty_fill.py"
    target.write_text(
        "def target() -> str:\n    return 'a'.center(3, '')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_center_reports_empty_fill_type_error(tmp_path: Path) -> None:
    target = tmp_path / "bytes_center_empty_fill.py"
    target.write_text(
        "def target() -> bytes:\n    return b'a'.center(3, b'')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_str_center_reports_noninteger_width(tmp_path: Path) -> None:
    target = tmp_path / "str_center_bad_width.py"
    target.write_text(
        "def target() -> str:\n    return 'a'.center('3')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_center_reports_noninteger_width(tmp_path: Path) -> None:
    target = tmp_path / "bytes_center_bad_width.py"
    target.write_text(
        "def target() -> bytes:\n    return b'a'.center('3')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_center_reports_nonbytes_fill(tmp_path: Path) -> None:
    target = tmp_path / "bytes_center_bad_fill.py"
    target.write_text(
        "def target() -> bytes:\n    return b'a'.center(3, 32)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
