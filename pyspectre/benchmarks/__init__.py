"""Benchmark package for PySpectre.
Provides performance benchmarking, regression testing, and profiling.
"""

from pyspectre.benchmarks.suite import (
    Benchmark,
    BenchmarkCategory,
    BenchmarkComparator,
    BenchmarkReporter,
    BenchmarkResult,
    BenchmarkSuite,
    RegressionResult,
    benchmark,
    create_builtin_benchmarks,
    run_benchmarks,
)

__all__ = [
    "BenchmarkCategory",
    "BenchmarkResult",
    "BenchmarkSuite",
    "Benchmark",
    "benchmark",
    "BenchmarkReporter",
    "RegressionResult",
    "BenchmarkComparator",
    "create_builtin_benchmarks",
    "run_benchmarks",
]
