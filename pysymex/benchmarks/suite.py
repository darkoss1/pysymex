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

"""Benchmarking suite for pysymex.
Provides performance benchmarks, regression testing, and profiling
tools for symbolic execution performance analysis.

This module is a re-export hub. Actual implementations live in
``suite_types`` (data classes / enums) and ``suite_core`` (logic).
"""

from pysymex.benchmarks.suite_core import Benchmark as Benchmark
from pysymex.benchmarks.suite_core import BenchmarkComparator as BenchmarkComparator
from pysymex.benchmarks.suite_core import BenchmarkReporter as BenchmarkReporter
from pysymex.benchmarks.suite_core import BenchmarkSuite as BenchmarkSuite
from pysymex.benchmarks.suite_core import bench_branching as bench_branching
from pysymex.benchmarks.suite_core import (
    bench_constraint_hashing as bench_constraint_hashing,
)
from pysymex.benchmarks.suite_core import (
    bench_incremental_solver as bench_incremental_solver,
)
from pysymex.benchmarks.suite_core import (
    bench_linear_constraints as bench_linear_constraints,
)
from pysymex.benchmarks.suite_core import bench_loop_unrolling as bench_loop_unrolling
from pysymex.benchmarks.suite_core import bench_race_detection as bench_race_detection
from pysymex.benchmarks.suite_core import (
    bench_simple_arithmetic as bench_simple_arithmetic,
)
from pysymex.benchmarks.suite_core import bench_state_forking as bench_state_forking
from pysymex.benchmarks.suite_core import benchmark as benchmark
from pysymex.benchmarks.suite_core import (
    create_builtin_benchmarks as create_builtin_benchmarks,
)
from pysymex.benchmarks.suite_core import run_benchmarks as run_benchmarks
from pysymex.benchmarks.suite_types import BenchmarkCategory as BenchmarkCategory
from pysymex.benchmarks.suite_types import BenchmarkResult as BenchmarkResult
from pysymex.benchmarks.suite_types import RegressionResult as RegressionResult

__all__ = [
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
