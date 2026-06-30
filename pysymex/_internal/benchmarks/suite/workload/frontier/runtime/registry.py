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

"""Registration metadata for runtime frontier benchmark workloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.benchmarks.suite.core import Benchmark, BenchmarkSuite
from pysymex._internal.benchmarks.suite.types import BenchmarkCategory, BenchmarkMode
from pysymex._internal.benchmarks.suite.workload.frontier.runtime.benchmarks import (
    bench_frontier_runtime_cegis_core_reuse_pruning,
    bench_frontier_runtime_cegis_dominance_pruning,
    bench_frontier_runtime_cegis_exact_pruning,
    bench_frontier_runtime_pressure_compaction,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_FRONTIER_RUNTIME_MODES = frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS))


@dataclass(frozen=True, slots=True)
class _FrontierRuntimeBenchmarkSpec:
    """Metadata for one runtime frontier benchmark registration."""

    name: str
    func: Callable[[], object]
    category: BenchmarkCategory
    description: str
    tags: tuple[str, ...]


_FRONTIER_RUNTIME_BENCHMARKS = (
    _FrontierRuntimeBenchmarkSpec(
        name="cegis_exact",
        func=bench_frontier_runtime_cegis_exact_pruning,
        category=BenchmarkCategory.SOLVING,
        description="Runtime CEGIS exact UNSAT pruning plus execute selection",
        tags=("solver", "frontier", "cegis", "runtime"),
    ),
    _FrontierRuntimeBenchmarkSpec(
        name="cegis_dedupe",
        func=bench_frontier_runtime_cegis_dominance_pruning,
        category=BenchmarkCategory.MEMORY,
        description="Runtime CEGIS exact checkpoint-duplicate pruning plus execute selection",
        tags=("memory", "frontier", "cegis", "runtime", "dominance"),
    ),
    _FrontierRuntimeBenchmarkSpec(
        name="cegis_core",
        func=bench_frontier_runtime_cegis_core_reuse_pruning,
        category=BenchmarkCategory.SOLVING,
        description="Runtime CEGIS exact UNSAT-core reuse across live checkpoints",
        tags=("solver", "frontier", "cegis", "runtime", "core-reuse"),
    ),
    _FrontierRuntimeBenchmarkSpec(
        name="pressure_compact",
        func=bench_frontier_runtime_pressure_compaction,
        category=BenchmarkCategory.MEMORY,
        description="Default-threshold POLAR runtime pressure compaction",
        tags=("memory", "frontier", "polar", "runtime", "pressure"),
    ),
)


def add_frontier_runtime_benchmarks(suite: BenchmarkSuite) -> None:
    """Add runtime frontier benchmark cases to the built-in suite."""
    for benchmark_spec in _FRONTIER_RUNTIME_BENCHMARKS:
        suite.add(
            Benchmark(
                name=benchmark_spec.name,
                func=benchmark_spec.func,
                category=benchmark_spec.category,
                description=benchmark_spec.description,
                modes=_FRONTIER_RUNTIME_MODES,
                tags=benchmark_spec.tags,
            ),
        )
