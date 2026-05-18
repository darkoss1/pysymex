# pysymex: Python Symbolic Execution & Formal Verification
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

"""Benchmarking suite core infrastructure for pysymex.
Provides base classes and decorators for defining symbolic execution benchmarks.
"""

from __future__ import annotations

import gc
import statistics
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, TypeVar, runtime_checkable

from pysymex.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkResult,
)


def _bench_list_factory() -> list[Benchmark]:
    """Bench list factory."""
    return []


@runtime_checkable
class _BenchmarkMetricsResult(Protocol):
    """Protocol for benchmark function return payloads with metric keys."""

    def get(self, key: str, default: object = 0) -> object:
        """Return value associated with key when present."""
        return default


def _metric_int(payload: object, key: str) -> int:
    """Extract integer benchmark metric from a generic payload."""
    if not isinstance(payload, _BenchmarkMetricsResult):
        return 0
    raw_value = payload.get(key, 0)
    if isinstance(raw_value, int):
        return raw_value
    return 0


@dataclass
class BenchmarkSuite:
    """Collection of related benchmarks."""

    name: str
    description: str = ""
    benchmarks: list[Benchmark] = field(default_factory=_bench_list_factory)
    setup: Callable[[], None] | None = None
    teardown: Callable[[], None] | None = None

    def add(self, benchmark: Benchmark) -> None:
        """Add a benchmark to the suite."""
        self.benchmarks.append(benchmark)

    def run_all(
        self,
        iterations: int = 5,
        case_name: str | None = None,
        warmup: int = 1,
    ) -> list[BenchmarkResult]:
        """Run all benchmarks in the suite."""
        results: list[BenchmarkResult] = []
        if self.setup:
            self.setup()
        try:
            for bench in self.benchmarks:
                if case_name and bench.name != case_name:
                    continue
                result = bench.run(iterations=iterations, warmup=warmup)
                results.append(result)
        finally:
            if self.teardown:
                self.teardown()
        return results


F = TypeVar("F", bound=Callable[..., object])


class Benchmark:
    """A single benchmark test.
    Measures execution time, memory usage, and other metrics
    for a symbolic execution workload.
    """

    def __init__(
        self,
        name: str,
        func: Callable[[], object],
        category: BenchmarkCategory = BenchmarkCategory.END_TO_END,
        description: str = "",
    ) -> None:
        self.name = name
        self.func = func
        self.category = category
        self.description = description

    def run(
        self,
        iterations: int = 5,
        case_name: str | None = None,
        warmup: int = 1,
    ) -> BenchmarkResult:
        """Run the benchmark and collect metrics."""
        import platform
        from datetime import datetime

        times: list[float] = []
        peak_memory = 0.0
        total_allocated = 0.0
        result: object | None = None
        for _ in range(warmup):
            gc.collect()
            self.func()

        for _ in range(iterations):
            gc.collect()
            start = time.perf_counter()
            result = self.func()
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        gc.collect()
        tracemalloc.start()
        memory_result = self.func()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_memory = peak / (1024 * 1024)
        total_allocated = current / (1024 * 1024)
        del memory_result
        mean_time = statistics.mean(times)
        stddev_time = statistics.stdev(times) if len(times) > 1 else 0.0
        paths = _metric_int(result, "paths")
        instructions = _metric_int(result, "instructions")
        solver_calls = _metric_int(result, "solver_calls")
        return BenchmarkResult(
            name=self.name,
            category=self.category,
            elapsed_seconds=sum(times),
            min_seconds=min(times),
            max_seconds=max(times),
            mean_seconds=mean_time,
            stddev_seconds=stddev_time,
            peak_memory_mb=peak_memory,
            allocated_mb=total_allocated,
            paths_explored=paths,
            instructions_executed=instructions,
            solver_calls=solver_calls,
            iterations=iterations,
            warmup_iterations=warmup,
            timestamp=datetime.now().isoformat(),
            python_version=platform.python_version(),
            platform=platform.platform(),
        )


def benchmark(
    name: str | None = None,
    category: BenchmarkCategory = BenchmarkCategory.END_TO_END,
) -> Callable[[F], F]:
    """Decorator that registers a function as a benchmark.

    The decorated function acquires a ``_benchmark`` attribute holding
    a :class:`Benchmark` instance.

    Args:
        name: Benchmark name (defaults to the function name).
        category: Classification category.

    Returns:
        Decorator that leaves the original function unchanged.
    """

    def decorator(func: F) -> F:
        """Decorator."""
        bench_name = name or func.__name__
        setattr(
            func,
            "_benchmark",
            Benchmark(
                name=bench_name,
                func=func,
                category=category,
                description=func.__doc__ or "",
            ),
        )
        return func

    return decorator
