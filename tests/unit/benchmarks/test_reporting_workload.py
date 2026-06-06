from __future__ import annotations

from pysymex.benchmarks.suite.workload.reporting import bench_reporting_formatters


def test_reporting_formatter_workload_collects_issue_and_output_metrics() -> None:
    result = bench_reporting_formatters()

    assert result["issues"] == 12
    assert result["paths"] == 48
    assert result["solver_calls"] == 32
    assert result["instructions"] > 0
