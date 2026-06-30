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

"""Typed registration specs for built-in benchmark workloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.benchmarks.suite.types import BenchmarkCategory, BenchmarkMode

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.benchmarks.suite.core import Benchmark, BenchmarkSuite

QUICK_FULL_STRESS = frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL, BenchmarkMode.STRESS))
FULL_STRESS = frozenset((BenchmarkMode.FULL, BenchmarkMode.STRESS))
QUICK_FULL = frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL))
STRESS_ONLY = frozenset((BenchmarkMode.STRESS,))


@dataclass(frozen=True, slots=True)
class BenchmarkSpec:
    """Immutable metadata for one built-in benchmark registration."""

    name: str
    func: Callable[[], object]
    category: BenchmarkCategory
    description: str
    modes: frozenset[BenchmarkMode]
    tags: tuple[str, ...]
    stability: str = "stable"


def benchmark_from_spec(spec: BenchmarkSpec) -> Benchmark:
    """Create a runnable benchmark case from immutable registry metadata."""
    from pysymex._internal.benchmarks.suite.core import Benchmark

    return Benchmark(
        name=spec.name,
        func=spec.func,
        category=spec.category,
        description=spec.description,
        modes=spec.modes,
        tags=spec.tags,
        stability=spec.stability,
    )


def add_benchmark_specs(
    suite: BenchmarkSuite,
    benchmark_specs: tuple[BenchmarkSpec, ...],
) -> None:
    """Add typed benchmark specs to a suite without changing their order."""
    for benchmark_spec in benchmark_specs:
        suite.add(benchmark_from_spec(benchmark_spec))
