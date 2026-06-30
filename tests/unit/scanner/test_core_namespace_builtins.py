"""Scanner regressions for namespace-introspection builtin models."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_target_division_by_zero(target: Path) -> bool:
    """Return whether scanning *target* reports the target division sink."""
    result = scan_file(target, use_sandbox=False)
    return any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_locals_snapshot_preserves_nonzero_guard_relation(tmp_path: Path) -> None:
    """A value read through locals() remains related to its symbolic local."""
    target = tmp_path / "locals_guard_safe.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    namespace = locals()\n"
        "    if namespace['x'] != 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    assert _has_target_division_by_zero(target) is False


def test_locals_snapshot_preserves_zero_bug_relation(tmp_path: Path) -> None:
    """A feasible zero read through locals() still reaches the real bug."""
    target = tmp_path / "locals_guard_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    namespace = locals()\n"
        "    if namespace['x'] == 0:\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    assert _has_target_division_by_zero(target) is True
