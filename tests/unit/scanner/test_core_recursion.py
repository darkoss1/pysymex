"""Scanner regressions for adaptive interprocedural recursion handling."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_follows_concrete_recursion_beyond_old_depth_cap(tmp_path: Path) -> None:
    target = tmp_path / "deep_recursion_bug.py"
    target.write_text(
        "def recurse(n: int) -> int:\n"
        "    if n == 0:\n"
        "        return 1 // n\n"
        "    return recurse(n - 1)\n\n"
        "def entry() -> int:\n"
        "    return recurse(12)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_summarizes_exact_recursive_recurrence(tmp_path: Path) -> None:
    target = tmp_path / "recursive_recurrence.py"
    target.write_text(
        "def recurse(n: int) -> int:\n"
        "    return recurse(n)\n\n"
        "def entry() -> int:\n"
        "    return recurse(1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert result.error is None
    assert "unmodeled_call_abstraction" in result.degraded_passes
