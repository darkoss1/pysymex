"""Scanner regressions for bytes and bytearray membership semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytes_contains_bytes_true_skips_else(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_bytes_true.py"
    target.write_text(
        "def target() -> int:\n    if b'A' in bytes(b'A'):\n        return 1\n    return 10 // 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_contains_bytes_true_skips_else(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_contains_bytes_true.py"
    target.write_text(
        "def target() -> int:\n"
        "    if b'A' in bytearray(b'A'):\n"
        "        return 1\n"
        "    return 10 // 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_contains_invalid_int_reports_value_error(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_invalid_int.py"
    target.write_text(
        "def target() -> int:\n    return int(300 in bytes(b'A'))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytearray_contains_invalid_int_reports_value_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytearray_contains_invalid_int.py"
    target.write_text(
        "def target() -> int:\n    return int(300 in bytearray(b'A'))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytes_contains_str_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_str.py"
    target.write_text(
        "def target() -> int:\n    return int('A' in bytes(b'A'))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_dunder_contains_invalid_int_reports_value_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytes_dunder_contains_invalid_int.py"
    target.write_text(
        "def target() -> int:\n    return int(bytes(b'A').__contains__(300))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytearray_dunder_contains_str_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_dunder_contains_str.py"
    target.write_text(
        "def target() -> int:\n    return int(bytearray(b'A').__contains__('A'))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
