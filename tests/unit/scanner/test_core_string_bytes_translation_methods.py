"""Scanner regressions for exact string/bytes translation methods."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytes_expandtabs_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_expandtabs_head.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x01\\t'.expandtabs(4)\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_expandtabs_reports_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_expandtabs_empty.py"
    target.write_text(
        "def target() -> bytes:\n    return b''.expandtabs()[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_translate_preserves_nonzero_length(tmp_path: Path) -> None:
    target = tmp_path / "str_translate_nonzero.py"
    target.write_text(
        "def target() -> int:\n    text = 'a'.translate({97: 'b'})\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_translate_reports_deleted_empty_length(tmp_path: Path) -> None:
    target = tmp_path / "str_translate_delete.py"
    target.write_text(
        "def target() -> int:\n    text = 'a'.translate({97: None})\n    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_translate_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_translate_head.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x01'.translate(None)\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_translate_reports_deleted_empty_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_translate_delete.py"
    target.write_text(
        "def target() -> bytes:\n"
        "    data = b'\\x01'.translate(None, b'\\x01')\n"
        "    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_maketrans_translate_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_maketrans_translate.py"
    target.write_text(
        "def target() -> int:\n"
        "    table = bytes.maketrans(b'a', b'b')\n"
        "    data = b'a'.translate(table)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_maketrans_translate_preserves_nonzero_length(tmp_path: Path) -> None:
    target = tmp_path / "str_maketrans_translate.py"
    target.write_text(
        "def target() -> int:\n"
        "    table = ''.maketrans('a', 'b')\n"
        "    text = 'a'.translate(table)\n"
        "    return 10 // len(text)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytes_maketrans_reports_bad_lengths(tmp_path: Path) -> None:
    target = tmp_path / "bytes_maketrans_bad_lengths.py"
    target.write_text(
        "def target() -> bytes:\n    return bytes.maketrans(b'a', b'bc')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")
