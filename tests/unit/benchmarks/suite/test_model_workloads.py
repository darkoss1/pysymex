"""Tests for model and core-type benchmark workloads."""

from pysymex._internal.benchmarks.suite.workload.models import bench_scalar_carrier_construction


def test_scalar_carrier_benchmark_exercises_all_constructions() -> None:
    result = bench_scalar_carrier_construction()

    assert result["instructions"] == 5120
    assert result["carrier_checksum"] > 0
