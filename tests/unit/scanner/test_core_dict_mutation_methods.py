"""Scanner regressions for dict mutation method precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_pop_existing_key_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_existing_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    value = data.pop('k')\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_pop_existing_key_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_existing_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    value = data.pop('k')\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_pop_existing_key_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_pop_existing_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    alias = data\n"
        "    value = alias.pop('k')\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_pop_existing_key_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_pop_existing_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    alias = data\n"
        "    value = alias.pop('k')\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_pop_missing_default_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_missing_default_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    value = data.pop('missing', x)\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_pop_missing_default_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_missing_default_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    value = data.pop('missing', x)\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_pop_mod_key_prunes_safe_integer_value(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_mod_key_integer_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 2, 1: 1}\n"
        "    item = data.pop(value % 2, 3)\n"
        "    return 10 // item\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_pop_mod_key_reports_zero_integer_value(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_mod_key_integer_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 0, 1: 1}\n"
        "    item = data.pop(value % 2, 3)\n"
        "    return 10 // item\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_pop_mod_key_prunes_safe_string_length(tmp_path: Path) -> None:
    target = tmp_path / "dict_pop_mod_key_string_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 'a', 1: 'bb'}\n"
        "    item = data.pop(value % 3, 'ccc')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_pop_mod_key_reports_empty_string_default_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_pop_mod_key_empty_default_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 'a', 1: 'bb'}\n"
        "    item = data.pop(value % 3, '')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_update_value_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_update_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data.update({'k': x})\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_update_value_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_update_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data.update({'k': x})\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_update_value_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_update_value_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    alias = data\n"
        "    alias.update({'k': x})\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_update_value_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_update_value_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    alias = data\n"
        "    alias.update({'k': x})\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_setdefault_existing_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_setdefault_existing_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    data.setdefault('k', 1)\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_setdefault_existing_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_setdefault_existing_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    data.setdefault('k', 1)\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_setdefault_missing_preserves_default_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_setdefault_missing_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'other': 1}\n"
        "    data.setdefault('k', x)\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_setdefault_missing_reports_zero_default_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_setdefault_missing_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'other': 1}\n"
        "    data.setdefault('k', x)\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_setdefault_mod_key_prunes_safe_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_setdefault_mod_key_integer_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 2, 1: 1}\n"
        "    item = data.setdefault(value % 2, 3)\n"
        "    return 10 // item\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_setdefault_mod_key_reports_zero_integer_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_setdefault_mod_key_integer_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 0, 1: 1}\n"
        "    item = data.setdefault(value % 2, 3)\n"
        "    return 10 // item\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_setdefault_mod_key_prunes_safe_string_length(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_setdefault_mod_key_string_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 'a', 1: 'bb'}\n"
        "    item = data.setdefault(value % 3, 'ccc')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_dict_setdefault_mod_key_reports_empty_string_default_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_setdefault_mod_key_empty_default_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    data = {0: 'a', 1: 'bb'}\n"
        "    item = data.setdefault(value % 3, '')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
    assert result.degraded_passes == []


def test_scan_file_alias_dict_setdefault_existing_preserves_value_guard(
    tmp_path: Path,
) -> None:
    target = tmp_path / "alias_dict_setdefault_existing_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    alias = data\n"
        "    alias.setdefault('k', 1)\n"
        "    if data['k'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_setdefault_existing_reports_zero_value_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "alias_dict_setdefault_existing_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    alias = data\n"
        "    alias.setdefault('k', 1)\n"
        "    if data['k'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_clear_then_read_reports_key_error(tmp_path: Path) -> None:
    target = tmp_path / "dict_clear_then_read_key_error.py"
    target.write_text(
        "def target(x: int) -> int:\n    data = {'k': x}\n    data.clear()\n    return data['k']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_clear_then_read_reports_key_error(tmp_path: Path) -> None:
    target = tmp_path / "alias_dict_clear_then_read_key_error.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    alias = data\n"
        "    alias.clear()\n"
        "    return data['k']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_clear_get_default_preserves_default_guard(tmp_path: Path) -> None:
    target = tmp_path / "dict_clear_get_default_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data.clear()\n"
        "    value = data.get('k', x)\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_clear_get_default_reports_zero_default_bug(tmp_path: Path) -> None:
    target = tmp_path / "dict_clear_get_default_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': 1}\n"
        "    data.clear()\n"
        "    value = data.get('k', x)\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")
