"""Scanner regressions for builtin constructor precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_division_by_zero(result: object, function_name: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == function_name
        for issue in issues
    )


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_constructor_copy_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_constructor_copy_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = list(values)\n"
        "    if copied[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_constructor_copy_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_constructor_copy_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = list(values)\n"
        "    if copied[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_tuple_constructor_copy_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_constructor_copy_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = tuple(values)\n"
        "    if copied[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_tuple_constructor_copy_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_constructor_copy_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = tuple(values)\n"
        "    if copied[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_sorted_single_item_preserves_guard(tmp_path: Path) -> None:
    target = tmp_path / "sorted_single_item_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    sorted_values = sorted(values)\n"
        "    if sorted_values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_sorted_single_item_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "sorted_single_item_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    sorted_values = sorted(values)\n"
        "    if sorted_values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_sorted_literal_index_preserves_concrete_length(tmp_path: Path) -> None:
    target = tmp_path / "sorted_literal_index.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = sorted([3, 1, 2])\n"
        "    result = values[0]\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_reversed_single_item_preserves_guard(tmp_path: Path) -> None:
    target = tmp_path / "reversed_single_item_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    reversed_values = list(reversed(values))\n"
        "    if reversed_values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_reversed_single_item_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "reversed_single_item_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    reversed_values = list(reversed(values))\n"
        "    if reversed_values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_enumerate_pair_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_pair_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    pairs = list(enumerate(values))\n"
        "    if pairs[0][1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_enumerate_pair_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_pair_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    pairs = list(enumerate(values))\n"
        "    if pairs[0][1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_zip_pair_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "zip_pair_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    pairs = list(zip(values, [1]))\n"
        "    if pairs[0][0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_zip_pair_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "zip_pair_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    pairs = list(zip(values, [1]))\n"
        "    if pairs[0][0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_filter_none_single_item_len_guard(tmp_path: Path) -> None:
    target = tmp_path / "filter_none_single_item_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    filtered = list(filter(None, values))\n"
        "    if len(filtered) > 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_filter_none_single_item_zero_len_bug(tmp_path: Path) -> None:
    target = tmp_path / "filter_none_single_item_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    filtered = list(filter(None, values))\n"
        "    if len(filtered) == 0:\n"
        "        return 10 // x\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_copy_method_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_copy_method_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = values.copy()\n"
        "    if copied[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_copy_method_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_copy_method_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    copied = values.copy()\n"
        "    if copied[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_add_empty_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_add_empty_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    combined = values + []\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_add_empty_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_add_empty_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    combined = values + []\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_mul_one_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_mul_one_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = values * 1\n"
        "    if repeated[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_mul_one_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_mul_one_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = values * 1\n"
        "    if repeated[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_mul_two_preserves_repeated_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_mul_two_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = values * 2\n"
        "    if repeated[1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_mul_two_reports_repeated_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_mul_two_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = values * 2\n"
        "    if repeated[1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_reflected_list_mul_one_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "reflected_list_mul_one_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = 1 * values\n"
        "    if repeated[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_reflected_list_mul_one_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "reflected_list_mul_one_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    repeated = 1 * values\n"
        "    if repeated[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_add_nonempty_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_add_nonempty_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    combined = values + [1]\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_list_add_nonempty_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_add_nonempty_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    combined = values + [1]\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
