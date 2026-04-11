# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Benchmark package for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides performance benchmarking, regression testing, and profiling.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.benchmarks.suite import (
        Benchmark as Benchmark,
        BenchmarkCategory as BenchmarkCategory,
        BenchmarkComparator as BenchmarkComparator,
        BenchmarkReporter as BenchmarkReporter,
        BenchmarkResult as BenchmarkResult,
        BenchmarkSuite as BenchmarkSuite,
        RegressionResult as RegressionResult,
        benchmark as benchmark,
        create_builtin_benchmarks as create_builtin_benchmarks,
        run_benchmarks as run_benchmarks,
    )

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


def __getattr__(name: str) -> object:
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
