"""Benchmarking suite for pysymex.
Provides performance benchmarks, regression testing, and profiling
tools for symbolic execution performance analysis.

This module is a re-export hub. Actual implementations live in
``suite_types`` (data classes / enums) and ``suite_core`` (logic).
"""

from pysymex.benchmarks.suite_types import BenchmarkCategory as BenchmarkCategory

from pysymex.benchmarks.suite_types import BenchmarkResult as BenchmarkResult

from pysymex.benchmarks.suite_types import RegressionResult as RegressionResult

from pysymex.benchmarks.suite_core import Benchmark as Benchmark

from pysymex.benchmarks.suite_core import BenchmarkComparator as BenchmarkComparator

from pysymex.benchmarks.suite_core import BenchmarkReporter as BenchmarkReporter

from pysymex.benchmarks.suite_core import BenchmarkSuite as BenchmarkSuite

from pysymex.benchmarks.suite_core import benchmark as benchmark

from pysymex.benchmarks.suite_core import create_builtin_benchmarks as create_builtin_benchmarks

from pysymex.benchmarks.suite_core import run_benchmarks as run_benchmarks


from pysymex.benchmarks.suite_core import bench_simple_arithmetic as bench_simple_arithmetic

from pysymex.benchmarks.suite_core import bench_branching as bench_branching

from pysymex.benchmarks.suite_core import bench_loop_unrolling as bench_loop_unrolling

from pysymex.benchmarks.suite_core import bench_linear_constraints as bench_linear_constraints

from pysymex.benchmarks.suite_core import bench_incremental_solver as bench_incremental_solver

from pysymex.benchmarks.suite_core import bench_state_forking as bench_state_forking

from pysymex.benchmarks.suite_core import bench_constraint_hashing as bench_constraint_hashing

from pysymex.benchmarks.suite_core import bench_race_detection as bench_race_detection

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
