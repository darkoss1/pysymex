from __future__ import annotations

from pysymex.execution.results.result import ExecutionResult
from pysymex.scanner.execution.passes import ExecutionMetrics


def test_execution_metrics_aggregates_solver_outcomes() -> None:
    """File-level scan metrics should preserve execution-result solver counters."""
    metrics = ExecutionMetrics()
    code = compile("x = 1", "<stats-aggregate>", "exec")

    metrics.record(
        code,
        ExecutionResult(
            paths_explored=1,
            solver_stats={
                "queries": 4,
                "sat_results": 2,
                "unsat_results": 1,
                "unknown_results": 1,
                "solver_time_ms": 12.5,
            },
        ),
    )
    metrics.record(
        code,
        ExecutionResult(
            paths_explored=1,
            solver_stats={
                "queries": 3,
                "sat_results": 1,
                "unsat_results": 1,
                "unknown_results": 1,
                "solver_time_ms": 7.5,
            },
        ),
    )

    assert metrics.solver_stats == {
        "queries": 7,
        "sat_results": 3,
        "unsat_results": 2,
        "unknown_results": 2,
        "solver_time_ms": 20.0,
    }
