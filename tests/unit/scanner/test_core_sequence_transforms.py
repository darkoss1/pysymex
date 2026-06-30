"""Scanner regressions for sequence transform precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_division_by_zero(result: object, function_name: str) -> bool:
    return _has_issue_kind(result, function_name, "DIVISION_BY_ZERO")


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_tuple_mul_one_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_mul_one_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    repeated = values * 1\n"
        "    if repeated[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")


def test_scan_file_tuple_mul_one_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_mul_one_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    repeated = values * 1\n"
        "    if repeated[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")


def test_scan_file_tuple_add_nonempty_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_add_nonempty_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = values + (1,)\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_add_nonempty_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_add_nonempty_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = values + (1,)\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_mul_then_add_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_mul_then_add_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = values * 1 + (1,)\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_tuple_mul_then_add_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_mul_then_add_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = values * 1 + (1,)\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_reflected_tuple_mul_then_add_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "reflected_tuple_mul_then_add_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = 1 * values + (1,)\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")


def test_scan_file_reflected_tuple_mul_then_add_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "reflected_tuple_mul_then_add_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x,)\n"
        "    combined = 1 * values + (1,)\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")


def test_scan_file_list_slice_head_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_slice_head_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x, 1]\n"
        "    head = values[:1]\n"
        "    if head[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")


def test_scan_file_list_slice_head_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_slice_head_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x, 1]\n"
        "    head = values[:1]\n"
        "    if head[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "NULL_DEREFERENCE")


def test_scan_file_tuple_slice_head_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_slice_head_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x, 1)\n"
        "    head = values[:1]\n"
        "    if head[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_slice_head_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_slice_head_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x, 1)\n"
        "    head = values[:1]\n"
        "    if head[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_step_slice_then_add_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_step_slice_then_add_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x, 1)\n"
        "    combined = values[::1] + (2,)\n"
        "    if combined[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_step_slice_then_add_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_step_slice_then_add_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (x, 1)\n"
        "    combined = values[::1] + (2,)\n"
        "    if combined[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_division_by_zero(result, "target")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
