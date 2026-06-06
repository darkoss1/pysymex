"""Scanner regressions for exact non-list iterable builtins."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_sum_bytes_preserves_nonzero_total(tmp_path: Path) -> None:
    target = tmp_path / "sum_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n    value = sum(b'\\x01')\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_sum_bytes_reports_zero_total_bug(tmp_path: Path) -> None:
    target = tmp_path / "sum_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n    value = sum(b'\\x00')\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_sum_string_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "sum_string_type_error.py"
    target.write_text(
        "def target() -> object:\n    return sum('a')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_sorted_bytes_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "sorted_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = sorted(b'\\x01')\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_sorted_string_empty_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "sorted_string_empty.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = sorted('')\n"
        "    if values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_min_bytes_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "min_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n    value = min(b'\\x01')\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_min_bytes_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "min_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n    value = min(b'\\x00')\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_min_empty_bytes_reports_value_error(tmp_path: Path) -> None:
    target = tmp_path / "min_empty_bytes.py"
    target.write_text(
        "def target() -> object:\n    return min(b'')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_max_dict_key_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "max_dict_key_nonzero.py"
    target.write_text(
        "def target() -> int:\n    value = max({1: 'a'})\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_min_string_preserves_truthy_character(tmp_path: Path) -> None:
    target = tmp_path / "min_string_truthy.py"
    target.write_text(
        "def target() -> int:\n"
        "    value = min('a')\n"
        "    if not value:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_any_zero_byte_skips_truthy_branch(tmp_path: Path) -> None:
    target = tmp_path / "any_zero_byte_safe.py"
    target.write_text(
        "def target() -> int:\n    if any(b'\\x00'):\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_any_zero_byte_reports_falsy_branch_bug(tmp_path: Path) -> None:
    target = tmp_path / "any_zero_byte_bug.py"
    target.write_text(
        "def target() -> int:\n    if not any(b'\\x00'):\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_all_empty_bytes_skips_negated_branch(tmp_path: Path) -> None:
    target = tmp_path / "all_empty_bytes_safe.py"
    target.write_text(
        "def target() -> int:\n    if not all(b''):\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_filter_none_zero_byte_is_empty(tmp_path: Path) -> None:
    target = tmp_path / "filter_none_zero_byte.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(filter(None, b'\\x00'))\n"
        "    if values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_filter_none_nonzero_byte_is_truthy(tmp_path: Path) -> None:
    target = tmp_path / "filter_none_nonzero_byte.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(filter(None, b'\\x01'))\n"
        "    if not values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
