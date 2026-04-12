from __future__ import annotations

from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult, RegressionResult


def test_benchmark_result_computed_metrics_and_dict() -> None:
    result = BenchmarkResult(
        name="demo",
        category=BenchmarkCategory.ANALYSIS,
        elapsed_seconds=2.0,
        instructions_executed=200,
        paths_explored=10,
    )

    assert result.throughput == 100.0
    assert result.paths_per_second == 5.0
    data = result.to_dict()
    assert data["category"] == "ANALYSIS"
    assert data["throughput"] == 100.0


def test_regression_result_description_direction() -> None:
    slower = RegressionResult("b1", 1.0, 1.3, 30.0, True, 10.0)
    faster = RegressionResult("b1", 1.0, 0.7, -30.0, False, 10.0)
    assert slower.change_description == "30.0% slower"
    assert faster.change_description == "30.0% faster"

