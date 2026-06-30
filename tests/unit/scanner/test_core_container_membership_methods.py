"""Scanner regressions for explicit container membership method precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_explicit_dict_contains_symbolic_key_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_dict_contains_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 2, 1: 1}\n"
        "    key = 0 if value == 0 else 1\n"
        "    if not dict.__contains__(mapping, key):\n"
        "        return 1 // 0\n"
        "    return mapping[key]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_explicit_dict_contains_symbolic_bool_matches_int_keys(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_dict_contains_bool_safe.py"
    target.write_text(
        "def target(value: bool) -> int:\n"
        "    mapping = {0: 2, 1: 1}\n"
        "    if not dict.__contains__(mapping, value):\n"
        "        return 1 // 0\n"
        "    return mapping[value]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_explicit_dict_contains_symbolic_key_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_dict_contains_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    mapping = {0: 2}\n"
        "    key = 0 if value == 0 else 1\n"
        "    if not dict.__contains__(mapping, key):\n"
        "        return 1 // 0\n"
        "    return mapping[key]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_explicit_tuple_contains_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_contains_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0, 1)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not tuple.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_tuple_contains_symbolic_bool_matches_int_items(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_contains_bool_safe.py"
    target.write_text(
        "def target(value: bool) -> int:\n"
        "    items = (0, 1)\n"
        "    if not tuple.__contains__(items, value):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_tuple_contains_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_contains_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0,)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not tuple.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_contains_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_contains_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0, 1]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not list.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_contains_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_contains_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not list.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_frozenset_contains_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_frozenset_contains_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = frozenset((0, 1))\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not frozenset.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_frozenset_contains_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_frozenset_contains_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = frozenset((0,))\n"
        "    needle = 0 if value == 0 else 1\n"
        "    if not frozenset.__contains__(items, needle):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_count_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_count_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0, 1]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    count = list.count(items, needle)\n"
        "    return 1 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_count_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_count_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    count = list.count(items, needle)\n"
        "    return 1 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_tuple_count_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_count_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0, 1)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    count = tuple.count(items, needle)\n"
        "    return 1 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_tuple_count_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_count_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0,)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    count = tuple.count(items, needle)\n"
        "    return 1 // count\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_index_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_index_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0, 1]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    idx = list.index(items, needle)\n"
        "    return 1 // (idx + 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "VALUE_ERROR")
    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_list_index_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_list_index_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = [0]\n"
        "    needle = 0 if value == 0 else 1\n"
        "    return list.index(items, needle)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_explicit_tuple_index_symbolic_value_prunes_present_domain(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_index_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0, 1)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    idx = tuple.index(items, needle)\n"
        "    return 1 // (idx + 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "VALUE_ERROR")
    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_explicit_tuple_index_symbolic_value_reports_missing_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_index_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    items = (0,)\n"
        "    needle = 0 if value == 0 else 1\n"
        "    return tuple.index(items, needle)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")
