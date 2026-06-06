"""Scanner regressions for exact bytearray transform payloads."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytearray_upper_preserves_nonzero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_upper_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'a').upper()\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_upper_reports_zero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_upper_zero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x00').upper()\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_replace_preserves_nonzero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_replace_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x00').replace(b'\\x00', b'\\x01')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_replace_reports_zero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_replace_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01').replace(b'\\x01', b'\\x00')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_strip_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_strip_empty.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x00').strip(b'\\x00')\n"
        "    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_strip_preserves_nonzero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_strip_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x00A\\x00').strip(b'\\x00')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
