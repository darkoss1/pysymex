from __future__ import annotations

from pysymex._internal.benchmarks.suite.workload.execution import (
    bench_bytecode_exception_entries_cache_hits,
    bench_bytecode_line_mapping_cache_hits,
)
from pysymex._internal.benchmarks.suite.workload.solver import (
    bench_exact_literal_cache_hits,
    bench_sat_cache_hits,
    bench_simple_arithmetic,
    bench_unsat_subset_cache_hits,
)


def test_simple_arithmetic_benchmark_reports_sat_query() -> None:
    result = bench_simple_arithmetic()

    assert result["solver_calls"] == 1
    assert result["solver_sat"] == 1
    assert result["solver_unknown"] == 0


def test_bytecode_line_mapping_cache_benchmark_reports_hits() -> None:
    result = bench_bytecode_line_mapping_cache_hits()

    assert result["solver_calls"] == 0
    assert result["cache_hits"] == result["paths"] - 1
    assert result["instructions"] > result["paths"]


def test_bytecode_exception_entries_cache_benchmark_reports_hits() -> None:
    result = bench_bytecode_exception_entries_cache_hits()

    assert result["solver_calls"] == 0
    assert result["cache_hits"] == result["instructions"] - 1


def test_solver_sat_cache_benchmark_uses_one_real_solver_query() -> None:
    result = bench_sat_cache_hits()

    assert result["solver_calls"] == 1
    assert result["solver_sat"] == 1
    assert result["solver_unknown"] == 0
    assert result["cache_hits"] == result["instructions"] - 1


def test_solver_exact_literal_cache_benchmark_avoids_solver_queries() -> None:
    result = bench_exact_literal_cache_hits()

    assert result["solver_calls"] == 0
    assert result["instructions"] > 1


def test_solver_unsat_subset_cache_benchmark_uses_one_real_solver_query() -> None:
    result = bench_unsat_subset_cache_hits()

    assert result["solver_calls"] == 1
    assert result["solver_unsat"] == 1
    assert result["solver_unknown"] == 0
    assert result["cache_hits"] == result["instructions"] - 1
