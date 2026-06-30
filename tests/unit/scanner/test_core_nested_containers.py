"""Tests for nested container scanner behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_nested_list_index_error(tmp_path: Path) -> None:
    target = tmp_path / "nested_list_index.py"
    target.write_text(
        "def target(row: int) -> int:\n"
        "    matrix = [[1, 2], [3, 4]]\n"
        "    if row == 1:\n"
        "        return matrix[row][4]\n"
        "    return matrix[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "INDEX_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_nested_dict_key_error(tmp_path: Path) -> None:
    target = tmp_path / "nested_dict_key.py"
    target.write_text(
        "def target(user_id: int) -> str:\n"
        "    users = {1: {'name': 'Ada'}}\n"
        "    if user_id == 1:\n"
        "        return users[user_id]['email']\n"
        "    return 'unknown'\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "KEY_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_does_not_report_nested_list_guarded_by_both_lengths(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_list_guarded.py"
    target.write_text(
        "def target(matrix: list[list[int]], row: int, col: int) -> int:\n"
        "    if row < 0 or row >= len(matrix):\n"
        "        return 0\n"
        "    if col < 0 or col >= len(matrix[row]):\n"
        "        return 0\n"
        "    return matrix[row][col]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "INDEX_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {4, 6}
        for issue in result.issues
    )


def test_scan_file_reports_nested_typed_dict_missing_inner_key(tmp_path: Path) -> None:
    target = tmp_path / "nested_typed_dict_missing_inner_key.py"
    target.write_text(
        "def target(payload: dict[str, dict[str, int]]) -> int:\n"
        "    if 'meta' in payload:\n"
        "        return payload['meta']['version']\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "KEY_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_does_not_report_nested_typed_dict_guarded_inner_key(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_typed_dict_guarded_inner_key.py"
    target.write_text(
        "def target(payload: dict[str, dict[str, int]]) -> int:\n"
        "    if 'meta' not in payload:\n"
        "        return 0\n"
        "    meta = payload['meta']\n"
        "    if 'version' not in meta:\n"
        "        return 0\n"
        "    return meta['version']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "KEY_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
