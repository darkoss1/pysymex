from __future__ import annotations

from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.scan.metrics import ExecutionMetrics


def test_execution_metrics_aggregates_solver_outcomes() -> None:
    """File-level scan metrics should preserve execution-result solver counters."""
    metrics = ExecutionMetrics()
    code = compile("x = 1", "<stats-aggregate>", "exec")

    metrics.record(
        code,
        ExecutionResult(
            paths_explored=1,
            paths_pruned=2,
            solver_stats={
                "queries": 4,
                "logical_queries": 6,
                "sat_results": 2,
                "unsat_results": 1,
                "unknown_results": 1,
                "cache_hits": 2,
                "z3_ast_cache_hits": 10,
                "z3_ast_cache_misses": 4,
                "solver_time_ms": 12.5,
                "detector_queries": {"cache_hits": 1, "cache_misses": 3},
            },
        ),
    )
    metrics.record(
        code,
        ExecutionResult(
            paths_explored=1,
            paths_pruned=1,
            solver_stats={
                "queries": 3,
                "logical_queries": 4,
                "sat_results": 1,
                "unsat_results": 1,
                "unknown_results": 1,
                "cache_hits": 1,
                "z3_ast_cache_hits": 5,
                "z3_ast_cache_misses": 2,
                "solver_time_ms": 7.5,
                "detector_queries": {"cache_hits": 2, "cache_misses": 2},
            },
        ),
    )

    assert metrics.solver_stats == {
        "queries": 7,
        "logical_queries": 10,
        "sat_results": 3,
        "unsat_results": 2,
        "unknown_results": 2,
        "cache_hits": 3,
        "z3_ast_cache_hits": 15,
        "z3_ast_cache_misses": 6,
        "solver_time_ms": 20.0,
        "detector_query_cache_hits": 3,
        "detector_query_cache_misses": 5,
        "detector_sink_attempts": 8,
    }
    assert metrics.paths_pruned == 3


def test_execution_metrics_remains_available_from_scan_module() -> None:
    """Existing scan-module imports should keep resolving to the metrics owner."""
    assert ExecutionMetrics is ExecutionMetrics
