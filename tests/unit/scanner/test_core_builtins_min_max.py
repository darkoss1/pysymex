"""Scanner regressions for min()/max() symbolic relations."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_respects_min_symbolic_relation_guard(tmp_path: Path) -> None:
    target = tmp_path / "min_relation_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    value = min([x, 1])\n"
        "    if value == 1:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_min_symbolic_relation_bug(tmp_path: Path) -> None:
    target = tmp_path / "min_relation_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    value = min([x, 1])\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_respects_max_symbolic_relation_guard(tmp_path: Path) -> None:
    target = tmp_path / "max_relation_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    value = max([x, -1])\n"
        "    if value == -1:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_max_symbolic_relation_bug(tmp_path: Path) -> None:
    target = tmp_path / "max_relation_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    value = max([x, -1])\n"
        "    if value == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )
