# pysymex: Python Symbolic Execution & Formal Verification
from __future__ import annotations

from pysymex.benchmarks.suite.comparison import BenchmarkComparator
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult


def test_comparator_detects_regressions() -> None:
    baseline = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.0, mean_seconds=1.0),
    ]
    current = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.3, mean_seconds=1.3),
    ]

    regressions = BenchmarkComparator(threshold_percent=10.0).compare(baseline, current)
    assert len(regressions) == 1
    assert regressions[0].is_regression is True
    assert "30.0% slower" in regressions[0].change_description
