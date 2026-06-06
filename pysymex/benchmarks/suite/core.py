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

"""Core benchmark suite primitives.

This module owns benchmark execution, timing, memory sampling, and suite-level
filtering. Workload modules provide concrete PySyMex cases.
"""

from __future__ import annotations

import gc
import platform
import statistics
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, TypeVar, runtime_checkable

from pysymex.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkEvent,
    BenchmarkMode,
    BenchmarkResult,
    BenchmarkStatus,
)

ProgressCallback = Callable[[BenchmarkEvent], None]


def _bench_list_factory() -> list[Benchmark]:
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
    if isinstance(raw_value, bool):
        return 0
    if isinstance(raw_value, int):
        return raw_value
    return 0


def _now_iso() -> str:
    """Return a stable ISO timestamp for benchmark result metadata."""
    return datetime.now().isoformat()


def _platform_name() -> str:
    """Return platform metadata for benchmark result records."""
    return platform.platform()


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
        mode: BenchmarkMode | None = BenchmarkMode.QUICK,
        category: BenchmarkCategory | None = None,
        progress: ProgressCallback | None = None,
    ) -> list[BenchmarkResult]:
        """Run all benchmarks in the suite."""
        selected = self.select(mode=mode, case_name=case_name, category=category)
        results: list[BenchmarkResult] = []
        if self.setup:
            self.setup()
        try:
            total = len(selected)
            for index, bench in enumerate(selected, start=1):
                result = bench.run(
                    iterations=iterations,
                    warmup=warmup,
                    progress=progress,
                    completed=index,
                    total=total,
                )
                results.append(result)
        finally:
            if self.teardown:
                self.teardown()
        return results

    def select(
        self,
        *,
        mode: BenchmarkMode | None,
        case_name: str | None = None,
        category: BenchmarkCategory | None = None,
    ) -> list[Benchmark]:
        """Return benchmarks matching the requested case, category, and mode."""
        selected: list[Benchmark] = []
        for benchmark_case in self.benchmarks:
            if (
                case_name
                and case_name != benchmark_case.name
                and case_name not in benchmark_case.aliases
            ):
                continue
            if category is not None and benchmark_case.category is not category:
                continue
            if case_name is None and mode is not None and mode not in benchmark_case.modes:
                continue
            selected.append(benchmark_case)
        return selected


F = TypeVar("F", bound=Callable[..., object])


class Benchmark:
    """One benchmark workload with timing, memory, and metric collection."""

    def __init__(
        self,
        name: str,
        func: Callable[[], object],
        category: BenchmarkCategory = BenchmarkCategory.END_TO_END,
        description: str = "",
        modes: frozenset[BenchmarkMode] | None = None,
        tags: tuple[str, ...] = (),
        stability: str = "stable",
        aliases: tuple[str, ...] = (),
    ) -> None:
        """Initialize a benchmark case."""
        self.name = name
        self.func = func
        self.category = category
        self.description = description
        self.modes = modes or frozenset((BenchmarkMode.QUICK, BenchmarkMode.FULL))
        self.tags = tags
        self.stability = stability
        self.aliases = aliases

    def run(
        self,
        iterations: int = 5,
        case_name: str | None = None,
        warmup: int = 1,
        progress: ProgressCallback | None = None,
        completed: int = 1,
        total: int = 1,
    ) -> BenchmarkResult:
        """Run the benchmark and collect metrics."""
        del case_name
        iterations = max(1, iterations)
        warmup = max(0, warmup)
        times: list[float] = []
        result: object | None = None
        self._emit(progress, "start", completed, total)
        try:
            for index in range(warmup):
                gc.collect()
                self.func()
                self._emit(progress, "warmup", completed, total, message=str(index + 1))

            for index in range(iterations):
                gc.collect()
                start = time.perf_counter()
                result = self.func()
                elapsed = time.perf_counter() - start
                times.append(elapsed)
                self._emit(progress, "iteration", completed, total, elapsed, str(index + 1))

            gc.collect()
            tracemalloc.start()
            try:
                memory_result = self.func()
                current, peak = tracemalloc.get_traced_memory()
                del memory_result
            finally:
                tracemalloc.stop()
        except Exception as exc:
            self._emit(progress, "failed", completed, total, message=str(exc))
            return self._failure_result(times=times, iterations=iterations, warmup=warmup, exc=exc)

        peak_memory = peak / (1024 * 1024)
        total_allocated = current / (1024 * 1024)
        mean_time = statistics.mean(times)
        stddev_time = statistics.stdev(times) if len(times) > 1 else 0.0
        paths = _metric_int(result, "paths")
        instructions = _metric_int(result, "instructions")
        solver_calls = _metric_int(result, "solver_calls")
        solver_sat = _metric_int(result, "solver_sat")
        solver_unsat = _metric_int(result, "solver_unsat")
        solver_unknown = _metric_int(result, "solver_unknown")
        issue_count = _metric_int(result, "issues")
        benchmark_result = BenchmarkResult(
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
            solver_sat=solver_sat,
            solver_unsat=solver_unsat,
            solver_unknown=solver_unknown,
            issue_count=issue_count,
            iterations=iterations,
            warmup_iterations=warmup,
            timestamp=datetime.now().isoformat(),
            python_version=platform.python_version(),
            platform=_platform_name(),
            tags=self.tags,
            stability=self.stability,
        )
        self._emit(progress, "finished", completed, total, mean_time)
        return benchmark_result

    def _failure_result(
        self,
        *,
        times: list[float],
        iterations: int,
        warmup: int,
        exc: Exception,
    ) -> BenchmarkResult:
        """Build a result that preserves explicit benchmark failure state."""
        mean_time = statistics.mean(times) if times else 0.0
        return BenchmarkResult(
            name=self.name,
            category=self.category,
            elapsed_seconds=sum(times),
            min_seconds=min(times) if times else 0.0,
            max_seconds=max(times) if times else 0.0,
            mean_seconds=mean_time,
            stddev_seconds=statistics.stdev(times) if len(times) > 1 else 0.0,
            iterations=iterations,
            warmup_iterations=warmup,
            timestamp=_now_iso(),
            python_version=platform.python_version(),
            platform=_platform_name(),
            status=BenchmarkStatus.FAILED,
            failure=f"{type(exc).__name__}: {exc}",
            tags=self.tags,
            stability=self.stability,
        )

    def _emit(
        self,
        progress: ProgressCallback | None,
        phase: str,
        completed: int,
        total: int,
        elapsed_seconds: float = 0.0,
        message: str = "",
    ) -> None:
        """Emit a progress event if a callback is configured."""
        if progress is None:
            return
        progress(
            BenchmarkEvent(
                benchmark_name=self.name,
                category=self.category,
                phase=phase,
                completed=completed,
                total=total,
                elapsed_seconds=elapsed_seconds,
                message=message,
            )
        )


def benchmark(
    name: str | None = None,
    category: BenchmarkCategory = BenchmarkCategory.END_TO_END,
    modes: frozenset[BenchmarkMode] | None = None,
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
                modes=modes,
            ),
        )
        return func

    return decorator
