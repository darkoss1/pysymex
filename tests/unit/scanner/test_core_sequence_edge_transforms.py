"""Scanner regressions for exact sequence edge transforms."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_negative_index_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_negative_index_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    if values[-1] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_negative_index_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_negative_index_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    if values[-1] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_tail_slice_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_tail_slice_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    tail = values[-1:]\n"
        "    if tail[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_tail_slice_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_tail_slice_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    tail = values[-1:]\n"
        "    if tail[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_reverse_slice_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_reverse_slice_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    reverse = values[::-1]\n"
        "    if reverse[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_reverse_slice_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_reverse_slice_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [1, x]\n"
        "    reverse = values[::-1]\n"
        "    if reverse[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_reverse_slice_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_reverse_slice_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (1, x)\n"
        "    reverse = values[::-1]\n"
        "    if reverse[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_reverse_slice_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_reverse_slice_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = (1, x)\n"
        "    reverse = values[::-1]\n"
        "    if reverse[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_negative_repeat_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "negative_repeat_falsy.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    repeated = [x] * -1\n"
        "    if repeated:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_negative_repeat_index_reports_index_error(tmp_path: Path) -> None:
    target = tmp_path / "negative_repeat_index.py"
    target.write_text(
        "def target(x: int) -> object:\n    repeated = [x] * -1\n    return repeated[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")
