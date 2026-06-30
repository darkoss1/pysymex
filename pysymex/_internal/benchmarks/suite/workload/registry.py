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

"""Registration of built-in benchmark workloads."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.benchmarks.suite.workload.frontier.runtime.registry import (
    add_frontier_runtime_benchmarks,
)
from pysymex._internal.benchmarks.suite.workload.registry_post_frontier import (
    POST_FRONTIER_BENCHMARK_SPECS,
)
from pysymex._internal.benchmarks.suite.workload.registry_pre_frontier import (
    PRE_FRONTIER_BENCHMARK_SPECS,
)
from pysymex._internal.benchmarks.suite.workload.registry_specs import add_benchmark_specs

if TYPE_CHECKING:
    from pysymex._internal.benchmarks.suite.core import BenchmarkSuite


def create_builtin_benchmarks() -> BenchmarkSuite:
    """Create the built-in benchmark suite with real Z3 workloads."""
    from pysymex._internal.benchmarks.suite.core import BenchmarkSuite

    suite = BenchmarkSuite(
        name="pysymex_builtin",
        description="Built-in pysymex benchmarks (real solver workloads)",
    )
    add_benchmark_specs(suite, PRE_FRONTIER_BENCHMARK_SPECS)
    add_frontier_runtime_benchmarks(suite)
    add_benchmark_specs(suite, POST_FRONTIER_BENCHMARK_SPECS)
    return suite
