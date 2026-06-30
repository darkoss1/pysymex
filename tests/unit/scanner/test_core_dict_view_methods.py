"""Scanner regressions for dict view precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_values_list_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_values_list_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    values = list(data.values())\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_values_list_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_values_list_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    values = list(data.values())\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_live_dict_values_view_reflects_assignment(tmp_path: Path) -> None:
    target = tmp_path / "dict_values_live_assignment_bug.py"
    target.write_text(
        "def target(a: int, b: int) -> int:\n"
        "    data = {'den': 1, 'sentinel': 5}\n"
        "    values = data.values()\n"
        "    data['den'] = a - b\n"
        "    if a == b and 0 in values:\n"
        "        return 70 // data['den']\n"
        "    return len(data)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_keys_list_preserves_nonzero_key(tmp_path: Path) -> None:
    target = tmp_path / "dict_keys_list_safe.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = {1: 'x'}\n"
        "    keys = list(data.keys())\n"
        "    return 10 // keys[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_dict_keys_list_reports_zero_key_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_keys_list_bug.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = {0: 'x'}\n"
        "    keys = list(data.keys())\n"
        "    return 10 // keys[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_dict_items_list_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_items_list_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    items = list(data.items())\n"
        "    if items[0][1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_dict_items_list_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_items_list_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    items = list(data.items())\n"
        "    if items[0][1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_empty_dict_keys_view_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "dict_keys_empty_falsy.py"
    target.write_text(
        "def target() -> int:\n"
        "    keys = {}.keys()\n"
        "    if keys:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_empty_dict_values_view_reports_negated_branch(tmp_path: Path) -> None:
    target = tmp_path / "dict_values_empty_truthiness.py"
    target.write_text(
        "def target() -> int:\n    if not {}.values():\n        return 10 // 0\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_second_next_on_dict_keys_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "dict_keys_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = iter({1: 'x'}.keys())\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
