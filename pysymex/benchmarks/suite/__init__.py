# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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
"""

from pysymex.benchmarks.suite.comparison import BenchmarkComparator
from pysymex.benchmarks.suite.core import Benchmark
from pysymex.benchmarks.suite.core import BenchmarkSuite
from pysymex.benchmarks.suite.core import benchmark
from pysymex.benchmarks.suite.reporting import BenchmarkReporter
from pysymex.benchmarks.suite.runner import run_benchmarks
from pysymex.benchmarks.suite.types import BenchmarkCategory
from pysymex.benchmarks.suite.types import BenchmarkEvent
from pysymex.benchmarks.suite.types import BenchmarkMode
from pysymex.benchmarks.suite.types import BenchmarkResult
from pysymex.benchmarks.suite.types import BenchmarkStatus
from pysymex.benchmarks.suite.types import RegressionResult
from pysymex.benchmarks.suite.workload.cli import bench_cli_default_scan as bench_cli_default_scan
from pysymex.benchmarks.suite.workload.solver import (
    bench_branching as bench_branching,
)
from pysymex.benchmarks.suite.workload.solver import (
    bench_constraint_hashing as bench_constraint_hashing,
)
from pysymex.benchmarks.suite.workload.execution import (
    bench_executor_core_branching as bench_executor_core_branching,
)
from pysymex.benchmarks.suite.workload.execution import (
    bench_executor_core_function as bench_executor_core_function,
)
from pysymex.benchmarks.suite.workload.solver import (
    bench_incremental_solver as bench_incremental_solver,
)
from pysymex.benchmarks.suite.workload.solver import (
    bench_linear_constraints as bench_linear_constraints,
)
from pysymex.benchmarks.suite.workload.solver import bench_loop_unrolling as bench_loop_unrolling
from pysymex.benchmarks.suite.workload.analysis import bench_race_detection as bench_race_detection
from pysymex.benchmarks.suite.workload.solver import (
    bench_simple_arithmetic as bench_simple_arithmetic,
)
from pysymex.benchmarks.suite.workload.execution import bench_state_forking as bench_state_forking
from pysymex.benchmarks.suite.workload.registry import (
    create_builtin_benchmarks,
)

__all__ = [
    "Benchmark",
    "BenchmarkCategory",
    "BenchmarkComparator",
    "BenchmarkEvent",
    "BenchmarkMode",
    "BenchmarkReporter",
    "BenchmarkResult",
    "BenchmarkStatus",
    "BenchmarkSuite",
    "RegressionResult",
    "benchmark",
    "create_builtin_benchmarks",
    "run_benchmarks",
]
