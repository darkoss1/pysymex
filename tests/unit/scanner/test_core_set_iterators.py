"""Scanner regressions for set and frozenset iterator precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_next_set_iterator_preserves_nonzero_member(tmp_path: Path) -> None:
    target = tmp_path / "set_iterator_nonzero.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter({1}))\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_next_set_iterator_reports_zero_member_bug(tmp_path: Path) -> None:
    target = tmp_path / "set_iterator_zero.py"
    target.write_text(
        "def target() -> int:\n    value = next(iter({0}))\n    return 10 // value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_set_constructor_preserves_nonzero_member(tmp_path: Path) -> None:
    target = tmp_path / "list_set_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list({1})\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_set_constructor_reports_zero_member_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_set_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list({0})\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_frozenset_constructor_preserves_nonzero_member(
    tmp_path: Path,
) -> None:
    target = tmp_path / "list_frozenset_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(frozenset({1}))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_frozenset_constructor_reports_zero_member_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "list_frozenset_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(frozenset({0}))\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_set_constructor_reports_unhashable_member(tmp_path: Path) -> None:
    target = tmp_path / "set_unhashable_member.py"
    target.write_text(
        "def target() -> object:\n    return set([[1]])\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_frozenset_constructor_reports_unhashable_member(
    tmp_path: Path,
) -> None:
    target = tmp_path / "frozenset_unhashable_member.py"
    target.write_text(
        "def target() -> object:\n    return frozenset([[1]])\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
