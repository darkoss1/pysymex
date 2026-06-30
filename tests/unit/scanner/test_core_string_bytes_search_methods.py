"""Scanner regressions for exact string and bytes search/count results."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_str_rfind_preserves_nonzero_index(tmp_path: Path) -> None:
    target = tmp_path / "str_rfind_nonzero.py"
    target.write_text(
        "def target() -> int:\n    index = 'ba'.rfind('a')\n    return 10 // index\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_str_rfind_reports_zero_index(tmp_path: Path) -> None:
    target = tmp_path / "str_rfind_zero.py"
    target.write_text(
        "def target() -> int:\n    index = 'ab'.rfind('a')\n    return 10 // index\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_find_preserves_nonzero_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_find_nonzero.py"
    target.write_text(
        "def target() -> int:\n    index = b'ba'.find(b'a')\n    return 10 // index\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_find_reports_zero_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_find_zero.py"
    target.write_text(
        "def target() -> int:\n    index = b'ab'.find(b'a')\n    return 10 // index\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_count_preserves_nonzero_count(tmp_path: Path) -> None:
    target = tmp_path / "bytes_count_nonzero.py"
    target.write_text(
        "def target() -> int:\n    count = b'aa'.count(b'a')\n    return 10 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_count_reports_zero_count(tmp_path: Path) -> None:
    target = tmp_path / "bytes_count_zero.py"
    target.write_text(
        "def target() -> int:\n    count = b'aa'.count(b'z')\n    return 10 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_index_missing_reports_value_error(tmp_path: Path) -> None:
    target = tmp_path / "bytes_index_missing.py"
    target.write_text(
        "def target() -> int:\n    return b'abc'.index(b'z')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytes_contains_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_false.py"
    target.write_text(
        "def target() -> int:\n    if b'z' in b'abc':\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_contains_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_true.py"
    target.write_text(
        "def target() -> int:\n    if b'a' in b'abc':\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_contains_int_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_int_false.py"
    target.write_text(
        "def target() -> int:\n    if 122 in b'abc':\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_contains_int_true_reports_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_contains_int_true.py"
    target.write_text(
        "def target() -> int:\n    if 97 in b'abc':\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
