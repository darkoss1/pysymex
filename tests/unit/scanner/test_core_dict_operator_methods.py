"""Scanner regressions for dict merge operator precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_or_preserves_right_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_or_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    merged = {'k': 1} | {'k': x}\n"
        "    if merged['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_or_reports_zero_right_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_or_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    merged = {'k': 1} | {'k': x}\n"
        "    if merged['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_ior_preserves_right_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_ior_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data |= {'k': x}\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_ior_reports_zero_right_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_ior_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data |= {'k': x}\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_ior_preserves_right_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_ior_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    alias = data\n"
        "    data |= {'k': x}\n"
        "    if alias['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_ior_reports_zero_right_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_ior_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    alias = data\n"
        "    data |= {'k': x}\n"
        "    if alias['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
