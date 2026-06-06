from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from pysymex.scanner.file import scan_file


def test_scan_reports_zero_division_after_or_short_circuit_guard(tmp_path: Path) -> None:
    target = tmp_path / "short_circuit_bug.py"
    target.write_text(
        dedent(
            """
            def target(x: int, y: int, z: int) -> int:
                delta = x - y
                if (delta == 0 or 64 // delta > z) and z == 1:
                    if x == y:
                        return 10 // delta
                return 0
            """
        ),
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=100)

    assert {issue["kind"] for issue in result.issues} == {"DIVISION_BY_ZERO"}
    assert result.degraded_passes == []


def test_scan_keeps_and_guarded_division_clean(tmp_path: Path) -> None:
    target = tmp_path / "short_circuit_safe.py"
    target.write_text(
        dedent(
            """
            def target(x: int, y: int, z: int) -> int:
                delta = x - y
                if delta != 0 and 64 // delta > z:
                    return 10 // delta
                return 0
            """
        ),
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, timeout=10, max_paths=100)

    assert result.issues == []
    assert result.degraded_passes == []
