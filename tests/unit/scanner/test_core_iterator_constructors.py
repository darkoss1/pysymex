"""Scanner regressions for constructors that consume explicit iterators."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_from_iterator_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "list_from_iterator_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = list(iter([x]))\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_from_iterator_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_from_iterator_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = list(iter([x]))\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_from_iterator_preserves_item_guard(tmp_path: Path) -> None:
    target = tmp_path / "tuple_from_iterator_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = tuple(iter([x]))\n"
        "    if values[0] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_tuple_from_iterator_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "tuple_from_iterator_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = tuple(iter([x]))\n"
        "    if values[0] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_constructor_consumes_iterator(tmp_path: Path) -> None:
    target = tmp_path / "list_consumes_iterator.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([x])\n"
        "    list(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_tuple_constructor_consumes_iterator(tmp_path: Path) -> None:
    target = tmp_path / "tuple_consumes_iterator.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([x])\n"
        "    tuple(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_consumed_iterator_default_preserves_guard(tmp_path: Path) -> None:
    target = tmp_path / "consumed_iterator_default_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([1])\n"
        "    list(iterator)\n"
        "    value = next(iterator, x)\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_consumed_iterator_default_reports_zero_default_bug(tmp_path: Path) -> None:
    target = tmp_path / "consumed_iterator_default_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([1])\n"
        "    list(iterator)\n"
        "    value = next(iterator, x)\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
