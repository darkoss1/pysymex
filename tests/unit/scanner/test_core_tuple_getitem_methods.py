"""Scanner regressions for tuple.__getitem__ precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_explicit_tuple_getitem_symbolic_index_prunes_safe_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_getitem_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    values = (2, 1)\n"
        "    index = 0 if value == 0 else 1\n"
        "    result = tuple.__getitem__(values, index)\n"
        "    if result == 0:\n"
        "        return 1 // 0\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_explicit_tuple_getitem_symbolic_index_reports_zero_value(
    tmp_path: Path,
) -> None:
    target = tmp_path / "explicit_tuple_getitem_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    values = (0, 1)\n"
        "    index = 0 if value == 0 else 1\n"
        "    result = tuple.__getitem__(values, index)\n"
        "    return 1 // result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
