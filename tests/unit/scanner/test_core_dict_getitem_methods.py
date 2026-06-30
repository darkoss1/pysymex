"""Scanner regressions for dict.__getitem__ precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_explicit_dict_getitem_symbolic_key_prunes_safe_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_dict_getitem_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 2, 1: 1}\n"
        "    key = 0 if value == 0 else 1\n"
        "    result = dict.__getitem__(mapping, key)\n"
        "    if result == 0:\n"
        "        return 1 // 0\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_explicit_dict_getitem_symbolic_key_reports_zero_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_dict_getitem_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 0, 1: 1}\n"
        "    key = 0 if value == 0 else 1\n"
        "    result = dict.__getitem__(mapping, key)\n"
        "    return 1 // result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_mod_keyed_dict_prunes_safe_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_keyed_dict_integer_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 2, 1: 1}\n"
        "    result = mapping[value % 2]\n"
        "    return 1 // result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_mod_keyed_dict_reports_zero_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_keyed_dict_integer_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 0, 1: 1}\n"
        "    result = mapping[value % 2]\n"
        "    return 1 // result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_mod_keyed_dict_prunes_safe_string_length(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_keyed_dict_string_length_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 'a', 1: 'bb'}\n"
        "    result = mapping[value % 2]\n"
        "    return 1 // len(result)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_mod_keyed_dict_reports_string_equality_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_keyed_dict_string_equality_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 'a', 1: 'bb'}\n"
        "    result = mapping[value % 2]\n"
        "    if result == 'bb':\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_mod_string_keyed_dict_prunes_safe_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_string_keyed_dict_integer_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    keys = ['a', 'b']\n"
        "    mapping = {'a': 2, 'b': 1}\n"
        "    key = keys[value % 2]\n"
        "    return 1 // mapping[key]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_mod_string_keyed_dict_reports_zero_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mod_string_keyed_dict_integer_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    keys = ['a', 'b']\n"
        "    mapping = {'a': 0, 'b': 1}\n"
        "    key = keys[value % 2]\n"
        "    return 1 // mapping[key]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []
