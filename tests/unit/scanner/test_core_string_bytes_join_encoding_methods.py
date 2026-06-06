"""Scanner regressions for exact string/bytes join and codec methods."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_str_join_preserves_nonzero_length(tmp_path: Path) -> None:
    target = tmp_path / "str_join_nonzero.py"
    target.write_text(
        "def target() -> int:\n    text = ','.join(['a', 'b'])\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_join_reports_empty_result_division(tmp_path: Path) -> None:
    target = tmp_path / "str_join_empty.py"
    target.write_text(
        "def target() -> int:\n    text = ''.join([])\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_join_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_join_head.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b','.join([b'\\x01', b'\\x02'])\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_join_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_join_empty.py"
    target.write_text(
        "def target() -> bytes:\n    data = b''.join([])\n    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_encode_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "str_encode_head.py"
    target.write_text(
        "def target() -> int:\n    data = 'a'.encode()\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_encode_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "str_encode_empty.py"
    target.write_text(
        "def target() -> int:\n    return ''.encode()[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_decode_preserves_nonzero_length(tmp_path: Path) -> None:
    target = tmp_path / "bytes_decode_nonzero.py"
    target.write_text(
        "def target() -> int:\n    text = b'a'.decode()\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_decode_reports_empty_length_division(tmp_path: Path) -> None:
    target = tmp_path / "bytes_decode_empty.py"
    target.write_text(
        "def target() -> int:\n    text = b''.decode()\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_encode_reports_bad_encoding_type(tmp_path: Path) -> None:
    target = tmp_path / "str_encode_bad_encoding.py"
    target.write_text(
        "def target() -> bytes:\n    return 'a'.encode(1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_decode_reports_bad_encoding_type(tmp_path: Path) -> None:
    target = tmp_path / "bytes_decode_bad_encoding.py"
    target.write_text(
        "def target() -> str:\n    return b'a'.decode(1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
