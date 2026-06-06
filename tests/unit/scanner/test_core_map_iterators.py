"""Scanner regressions for exact map() iterator behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_map_bool_zero_byte_preserves_false_item(tmp_path: Path) -> None:
    target = tmp_path / "map_bool_zero_byte.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(map(bool, b'\\x00'))\n"
        "    if values[0]:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_map_bool_nonzero_byte_preserves_true_item(tmp_path: Path) -> None:
    target = tmp_path / "map_bool_nonzero_byte.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list(map(bool, b'\\x01'))\n"
        "    if not values[0]:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_second_next_on_map_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "map_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = map(bool, b'\\x01')\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_map_int_string_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "map_int_string_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(map(int, '1'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_map_int_string_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "map_int_string_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(map(int, '0'))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
