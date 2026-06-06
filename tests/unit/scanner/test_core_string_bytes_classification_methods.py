"""Scanner regressions for exact string and bytes case/classification methods."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytes_upper_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_upper_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = b'a'.upper()\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_lower_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_lower_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = b'A'.lower()\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_isdigit_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_isdigit_false.py"
    target.write_text(
        "def target() -> int:\n    if b'a'.isdigit():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_isdigit_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_isdigit_true.py"
    target.write_text(
        "def target() -> int:\n    if b'1'.isdigit():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_isdigit_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "str_isdigit_false.py"
    target.write_text(
        "def target() -> int:\n    if 'a'.isdigit():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_isdigit_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "str_isdigit_true.py"
    target.write_text(
        "def target() -> int:\n    if '1'.isdigit():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_isascii_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "str_isascii_false.py"
    target.write_text(
        "def target() -> int:\n    if '\\u00e9'.isascii():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_isascii_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "str_isascii_true.py"
    target.write_text(
        "def target() -> int:\n    if 'a'.isascii():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_isascii_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_isascii_false.py"
    target.write_text(
        "def target() -> int:\n    if b'\\xff'.isascii():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_isascii_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_isascii_true.py"
    target.write_text(
        "def target() -> int:\n    if b'a'.isascii():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
