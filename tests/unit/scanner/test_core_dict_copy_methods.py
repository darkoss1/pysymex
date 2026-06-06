"""Scanner regressions for dict copy precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_copy_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_copy_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    copied = data.copy()\n"
        "    if copied['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_copy_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_copy_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    copied = data.copy()\n"
        "    if copied['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_copy_is_independent_from_original_update_guard(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_copy_original_update_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    copied = data.copy()\n"
        "    data.update({'k': 1})\n"
        "    if copied['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_copy_is_independent_from_original_update_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_copy_original_update_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    copied = data.copy()\n"
        "    data.update({'k': 1})\n"
        "    if copied['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
