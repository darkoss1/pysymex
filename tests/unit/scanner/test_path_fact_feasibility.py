from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from pysymex._internal.scanner.file import scan_file


def test_scan_uses_path_facts_for_redundant_and_contradictory_guards(
    tmp_path: Path,
) -> None:
    target = tmp_path / "path_fact_scan.py"
    target.write_text(
        dedent(
            """
            def redundant_and_contradictory_guards(x: int) -> int:
                total = 0
                if x >= 0:
                    if x > -1:
                        total += 1
                    if x < 0:
                        total += 100 // x
                    if x <= 2:
                        if x > 5:
                            total += 200 // (x - 6)
                return total


            def real_boundary_bug(x: int) -> int:
                if x >= 3:
                    if x <= 3:
                        return 10 // (x - 3)
                    if x < 3:
                        return 20 // x
                return 1
            """
        ),
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        timeout=10,
        max_paths=200,
        no_cache=True,
    )

    assert result.error is None
    assert result.degraded_passes == []
    assert result.paths_explored == 6
    assert {issue["kind"] for issue in result.issues} == {"DIVISION_BY_ZERO"}
    queries = result.solver_stats["queries"]
    assert isinstance(queries, int)
    assert queries <= 8
