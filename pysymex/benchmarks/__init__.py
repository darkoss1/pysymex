"""Benchmark package for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides performance benchmarking, regression testing, and profiling.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "Benchmark": ("pysymex.benchmarks.suite", "Benchmark"),
    "BenchmarkCategory": ("pysymex.benchmarks.suite", "BenchmarkCategory"),
    "BenchmarkComparator": ("pysymex.benchmarks.suite", "BenchmarkComparator"),
    "BenchmarkReporter": ("pysymex.benchmarks.suite", "BenchmarkReporter"),
    "BenchmarkResult": ("pysymex.benchmarks.suite", "BenchmarkResult"),
    "BenchmarkSuite": ("pysymex.benchmarks.suite", "BenchmarkSuite"),
    "RegressionResult": ("pysymex.benchmarks.suite", "RegressionResult"),
    "benchmark": ("pysymex.benchmarks.suite", "benchmark"),
    "create_builtin_benchmarks": ("pysymex.benchmarks.suite", "create_builtin_benchmarks"),
    "run_benchmarks": ("pysymex.benchmarks.suite", "run_benchmarks"),
}


def __getattr__(name: str) -> Any:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.benchmarks' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "Benchmark",
    "BenchmarkCategory",
    "BenchmarkComparator",
    "BenchmarkReporter",
    "BenchmarkResult",
    "BenchmarkSuite",
    "RegressionResult",
    "benchmark",
    "create_builtin_benchmarks",
    "run_benchmarks",
]
