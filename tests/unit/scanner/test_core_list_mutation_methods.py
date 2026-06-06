"""Scanner regressions for list mutation method precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_pop_default_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_pop_default_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    item = values.pop()\n"
        "    if item != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_pop_default_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_pop_default_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    item = values.pop()\n"
        "    if item == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_insert_front_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_insert_front_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    values.insert(0, x)\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_insert_front_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_insert_front_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    values.insert(0, x)\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_extend_suffix_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_extend_suffix_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    values.extend([x])\n"
        "    if values[1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_extend_suffix_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_extend_suffix_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    values.extend([x])\n"
        "    if values[1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_alias_insert_front_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_insert_front_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    alias = values\n"
        "    alias.insert(0, x)\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_alias_insert_front_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_insert_front_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    alias = values\n"
        "    alias.insert(0, x)\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_alias_extend_suffix_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_extend_suffix_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    alias = values\n"
        "    alias.extend([x])\n"
        "    if values[1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_alias_extend_suffix_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_extend_suffix_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1]\n"
        "    alias = values\n"
        "    alias.extend([x])\n"
        "    if values[1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_remove_prefix_preserves_shifted_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_remove_prefix_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    values.remove(1)\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_list_remove_prefix_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_remove_prefix_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    values.remove(1)\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_alias_remove_prefix_preserves_shifted_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_remove_prefix_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    alias = values\n"
        "    alias.remove(1)\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_alias_remove_prefix_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_remove_prefix_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    alias = values\n"
        "    alias.remove(1)\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
