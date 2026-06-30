"""Scanner regressions for lifecycle degradation and value-range confidence."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.execution.calls.construction_fallbacks import (
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
)
from pysymex._internal.scanner.file import scan_file


def test_scan_file_suppresses_range_warning_after_construction_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "construction_degraded_range_warning.py"
    target.write_text(
        "class Base:\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return Child(1)\n\n"
        "class Child(Base if True else object):\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value\n\n"
        "def target() -> int:\n"
        "    obj = Base(0)\n"
        "    denom = 0\n"
        "    if obj.denominator:\n"
        "        return 1 // denom\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert UNSUPPORTED_CONSTRUCTION_PROTOCOL in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and str(issue.get("message", "")).startswith("[Value Range]")
        for issue in result.issues
    )
