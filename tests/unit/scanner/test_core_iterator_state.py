"""Scanner regressions for explicit iterator state."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_next_first_item_preserves_value_guard(tmp_path: Path) -> None:
    target = tmp_path / "next_first_item_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([x])\n"
        "    value = next(iterator)\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_first_item_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "next_first_item_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([x])\n"
        "    value = next(iterator)\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_exhausted_iterator_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "next_exhausted_stop_iteration.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([x])\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_exhausted_default_preserves_default_guard(tmp_path: Path) -> None:
    target = tmp_path / "next_exhausted_default_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([1])\n"
        "    next(iterator)\n"
        "    value = next(iterator, x)\n"
        "    if value != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")


def test_scan_file_next_exhausted_default_reports_zero_default_bug(tmp_path: Path) -> None:
    target = tmp_path / "next_exhausted_default_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    iterator = iter([1])\n"
        "    next(iterator)\n"
        "    value = next(iterator, x)\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
