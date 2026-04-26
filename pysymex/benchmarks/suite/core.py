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

"""Benchmarking suite logic for pysymex.
Provides benchmark execution, reporting, comparison, and built-in workloads.
"""

from __future__ import annotations

import gc
import json
import statistics
import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypeVar, cast, runtime_checkable

from pysymex.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkResult,
    RegressionResult,
)

if TYPE_CHECKING:
    from pysymex._typing import StackValue


@runtime_checkable
class _BenchmarkMetricsResult(Protocol):
    """Protocol for benchmark function return payloads with metric keys."""

    def get(self, key: str, default: object = 0) -> object:
        """Return value associated with key when present."""
        ...


def _bench_list_factory() -> list[Benchmark]:
    """Bench list factory."""
    return []


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
            gc.disable()
            tracemalloc.start()
            start = time.perf_counter()
            result = self.func()
            elapsed = time.perf_counter() - start
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            gc.enable()
            times.append(elapsed)
            peak_memory = max(peak_memory, peak / (1024 * 1024))
            total_allocated += current / (1024 * 1024)
        mean_time = statistics.mean(times)
        stddev_time = statistics.stdev(times) if len(times) > 1 else 0.0
        paths = 0
        instructions = 0
        solver_calls = 0
        if isinstance(result, _BenchmarkMetricsResult):
            paths_val = result.get("paths", 0)
            instructions_val = result.get("instructions", 0)
            solver_calls_val = result.get("solver_calls", 0)
            paths = paths_val if isinstance(paths_val, int) else 0
            instructions = instructions_val if isinstance(instructions_val, int) else 0
            solver_calls = solver_calls_val if isinstance(solver_calls_val, int) else 0
        return BenchmarkResult(
            name=self.name,
            category=self.category,
            elapsed_seconds=sum(times),
            min_seconds=min(times),
            max_seconds=max(times),
            mean_seconds=mean_time,
            stddev_seconds=stddev_time,
            peak_memory_mb=peak_memory,
            allocated_mb=total_allocated / iterations,
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


class BenchmarkReporter:
    """Renders benchmark results in various output formats.

    All methods are ``@staticmethod``; no instance state is needed.
    """

    @staticmethod
    def to_console(results: list[BenchmarkResult]) -> None:
        """Print results to console."""
        print("\n" + "=" * 70)
        print("pysymex Benchmark Results")
        print("=" * 70)
        for result in results:
            print(f"\n{result.name} ({result.category.name})")
            print("-" * 40)
            print(f"  Mean time:     {result.mean_seconds * 1000:.2f} ms")
            print(f"  Std dev:       {result.stddev_seconds * 1000:.2f} ms")
            print(
                f"  Min/Max:       {result.min_seconds * 1000:.2f}/{result.max_seconds * 1000:.2f} ms"
            )
            print(f"  Peak memory:   {result.peak_memory_mb:.2f} MB")
            print(f"  Throughput:    {result.throughput:.0f} instr/sec")
            if result.paths_explored > 0:
                print(f"  Paths/sec:     {result.paths_per_second:.2f}")
        print("\n" + "=" * 70)

    @staticmethod
    def to_json(results: list[BenchmarkResult]) -> str:
        """Convert results to JSON."""
        return json.dumps(
            [r.to_dict() for r in results],
            indent=2,
        )

    @staticmethod
    def to_json_file(results: list[BenchmarkResult], path: Path) -> None:
        """Write results to JSON file."""
        path.write_text(BenchmarkReporter.to_json(results))

    @staticmethod
    def to_markdown(results: list[BenchmarkResult]) -> str:
        """Convert results to Markdown table."""
        lines = [
            "| Benchmark | Category | Mean (ms) | Std Dev | Peak Memory (MB) | Throughput |",
            "|-----------|----------|-----------|---------|------------------|------------|",
        ]
        for r in results:
            lines.append(
                f"| {r.name} | {r.category.name} | "
                f"{r.mean_seconds * 1000:.2f} | {r.stddev_seconds * 1000:.2f} | "
                f"{r.peak_memory_mb:.2f} | {r.throughput:.0f} instr/s |"
            )
        return "\n".join(lines)


class BenchmarkComparator:
    """Compare current benchmark results against a baseline for regressions.

    Attributes:
        threshold_percent: Percentage increase that is flagged as a
            regression.
    """

    def __init__(self, threshold_percent: float = 10.0) -> None:
        """
        Args:
            threshold_percent: Percent change that triggers regression.
        """
        self.threshold_percent = threshold_percent

    def compare(
        self,
        baseline: list[BenchmarkResult],
        current: list[BenchmarkResult],
    ) -> list[RegressionResult]:
        """Compare baseline to current results."""
        baseline_by_name = {r.name: r for r in baseline}
        results: list[RegressionResult] = []
        for curr in current:
            if curr.name not in baseline_by_name:
                continue
            base = baseline_by_name[curr.name]
            if base.mean_seconds > 0:
                change = ((curr.mean_seconds - base.mean_seconds) / base.mean_seconds) * 100
            else:
                change = 0.0
            is_regression = change > self.threshold_percent
            results.append(
                RegressionResult(
                    benchmark_name=curr.name,
                    baseline_mean=base.mean_seconds,
                    current_mean=curr.mean_seconds,
                    change_percent=change,
                    is_regression=is_regression,
                    threshold_percent=self.threshold_percent,
                )
            )
        return results

    def report_regressions(self, regressions: list[RegressionResult]) -> str:
        """Generate regression report."""
        lines = ["# Benchmark Comparison Report\n"]
        failures = [r for r in regressions if r.is_regression]
        if failures:
            lines.append(f"## [WARN] {len(failures)} Regression(s) Detected\n")
            for r in failures:
                lines.append(f"- **{r.benchmark_name}**: {r.change_description}")
                lines.append(f"  - Baseline: {r.baseline_mean * 1000:.2f} ms")
                lines.append(f"  - Current: {r.current_mean * 1000:.2f} ms\n")
        else:
            lines.append("## [OK] No Regressions Detected\n")
        lines.append("## All Results\n")
        for r in regressions:
            status = "[REGRESSION]" if r.is_regression else "[OK]"
            lines.append(f"{status} {r.benchmark_name}: {r.change_description}")
        return "\n".join(lines)


def create_builtin_benchmarks() -> BenchmarkSuite:
    """Create the built-in benchmark suite with real Z3 workloads.

    Returns:
        A :class:`BenchmarkSuite` containing all standard benchmarks.
    """
    suite = BenchmarkSuite(
        name="pysymex_builtin",
        description="Built-in pysymex benchmarks (real solver workloads)",
    )
    suite.add(
        Benchmark(
            name="simple_arithmetic",
            func=bench_simple_arithmetic,
            category=BenchmarkCategory.OPCODES,
            description="Basic arithmetic operations with Z3",
        )
    )
    suite.add(
        Benchmark(
            name="branching",
            func=bench_branching,
            category=BenchmarkCategory.PATHS,
            description="Path exploration with 20-way branch explosion",
        )
    )
    suite.add(
        Benchmark(
            name="loop_unrolling",
            func=bench_loop_unrolling,
            category=BenchmarkCategory.PATHS,
            description="Loop handling with constraint accumulation",
        )
    )
    suite.add(
        Benchmark(
            name="linear_constraints",
            func=bench_linear_constraints,
            category=BenchmarkCategory.SOLVING,
            description="100 linear integer constraints",
        )
    )
    suite.add(
        Benchmark(
            name="incremental_solver",
            func=bench_incremental_solver,
            category=BenchmarkCategory.SOLVING,
            description="Incremental solver push/pop performance",
        )
    )
    suite.add(
        Benchmark(
            name="state_forking",
            func=bench_state_forking,
            category=BenchmarkCategory.MEMORY,
            description="VMState CoW fork performance",
        )
    )
    suite.add(
        Benchmark(
            name="constraint_hashing",
            func=bench_constraint_hashing,
            category=BenchmarkCategory.SOLVING,
            description="Structural constraint hashing performance",
        )
    )
    suite.add(
        Benchmark(
            name="concurrency_race_detection",
            func=bench_race_detection,
            category=BenchmarkCategory.CONCURRENCY,
            description="Race detection with 10 operations",
        )
    )
    return suite


def bench_simple_arithmetic() -> dict[str, int]:
    """Benchmark: real Z3 arithmetic constraint solving."""
    import z3

    solver = z3.Solver()
    x, y = z3.Ints("x y")
    solver.add(x + y == 10)
    solver.add(x > 0, y > 0)
    solver.add(x * y > 15)
    solver.check()

    return {"instructions": 100, "paths": 1, "solver_calls": 1}


def bench_branching() -> dict[str, int]:
    """Benchmark: 20-way branch explosion with Z3."""
    import z3

    vars_ = [z3.Int(f"b{i}") for i in range(20)]
    solver = z3.Solver()
    solver.set("timeout", 5000)
    paths = 0
    for v in vars_:
        solver.push()
        solver.add(v > 0)
        if solver.check() == z3.sat:
            paths += 1
        solver.pop()
        solver.push()
        solver.add(v <= 0)
        if solver.check() == z3.sat:
            paths += 1
        solver.pop()

    return {"instructions": 200, "paths": paths, "solver_calls": 40}


def bench_loop_unrolling() -> dict[str, int]:
    """Benchmark: loop with accumulating constraints."""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)
    x = z3.Int("x")
    solver.add(x >= 0, x < 1000)
    paths = 0
    for i in range(50):
        solver.push()
        solver.add(x > i * 10)
        if solver.check() == z3.sat:
            paths += 1
        solver.pop()

    return {"instructions": 500, "paths": paths, "solver_calls": 50}


def bench_linear_constraints() -> dict[str, int]:
    """Benchmark: 100 linear integer constraints."""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 10000)
    vars_ = [z3.Int(f"v{i}") for i in range(100)]
    for i in range(99):
        solver.add(vars_[i] + 1 <= vars_[i + 1])
    solver.add(vars_[0] >= 0)
    solver.add(vars_[99] <= 1000)
    solver.check()

    return {"instructions": 100, "paths": 1, "solver_calls": 1}


def bench_incremental_solver() -> dict[str, int]:
    """Benchmark: IncrementalSolver push/pop performance."""
    try:
        from pysymex.core.solver.engine import IncrementalSolver
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    solver = IncrementalSolver(timeout_ms=5000)
    x, y = z3.Ints("x y")
    calls = 0

    for i in range(100):
        constraints = [x > i, y > i, x + y < i * 3 + 10]
        solver.is_sat(constraints)
        calls += 1

    return {"instructions": 300, "paths": 100, "solver_calls": calls}


def bench_state_forking() -> dict[str, int]:
    """Benchmark: VMState CoW fork performance."""
    try:
        from pysymex.core.state import VMState
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    state = VMState()
    for i in range(50):
        v = z3.Int(f"var_{i}")
        state.local_vars[f"var_{i}"] = cast("StackValue", v)
        state.add_constraint(v >= 0)

    forks = 0
    for _ in range(1000):
        state.fork()
        forks += 1

    return {"instructions": 1000, "paths": forks, "solver_calls": 0}


def bench_constraint_hashing() -> dict[str, int]:
    """Benchmark: structural constraint hashing vs string-based."""
    try:
        from pysymex.core.solver.constraints import ConstraintHasher, structural_hash
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    x, y, z_var = z3.Ints("x y z")
    constraints = [
        x + y > 10,
        y - z_var < 5,
        x * 2 == z_var,
        x >= 0,
        y >= 0,
        z_var >= 0,
        x + y + z_var < 100,
    ]

    hasher = ConstraintHasher()

    hashes = 0
    for _ in range(10000):
        structural_hash(constraints, hasher)
        hashes += 1

    return {"instructions": 10000, "paths": 0, "solver_calls": 0}


def bench_race_detection() -> dict[str, int]:
    """Benchmark: race detection with concurrent operations."""
    try:
        from pysymex.analysis.concurrency import ConcurrencyAnalyzer
    except ImportError:
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    analyzer = ConcurrencyAnalyzer(timeout_ms=5000)
    ops = 0

    for var_idx in range(5):
        addr = f"shared_var_{var_idx}"

        analyzer.record_write("thread_0", addr, f"val_{ops}")
        ops += 1

        analyzer.record_read("thread_1", addr)
        ops += 1

    analyzer.get_all_issues()
    return {"instructions": ops, "paths": 0, "solver_calls": 0}


def run_benchmarks(
    output_path: Path | None = None,
    baseline_path: Path | None = None,
    format: str = "console",
    iterations: int = 5,
    case_name: str | None = None,
) -> int:
    """Run the built-in benchmarks from the CLI.

    Args:
        output_path: Optional file path for JSON output.
        baseline_path: Optional baseline JSON for regression comparison.
        format: Output format (``console``, ``json``, ``markdown``).
        iterations: Number of timing iterations per benchmark.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.
    """
    suite = create_builtin_benchmarks()
    results = suite.run_all(iterations=iterations, case_name=case_name)
    if format == "json" and output_path:
        BenchmarkReporter.to_json_file(results, output_path)
    elif format == "markdown":
        print(BenchmarkReporter.to_markdown(results))
    else:
        BenchmarkReporter.to_console(results)
    if baseline_path and baseline_path.exists():
        baseline_data = json.loads(baseline_path.read_text())
        baseline = [
            BenchmarkResult(
                name=d["name"],
                category=BenchmarkCategory[d["category"]],
                elapsed_seconds=d["elapsed_seconds"],
                mean_seconds=d["mean_seconds"],
                stddev_seconds=d.get("stddev_seconds", 0),
                min_seconds=d.get("min_seconds", 0),
                max_seconds=d.get("max_seconds", 0),
            )
            for d in baseline_data
        ]
        comparator = BenchmarkComparator()
        regressions = comparator.compare(baseline, results)
        print(comparator.report_regressions(regressions))
        if any(r.is_regression for r in regressions):
            return 1
    return 0


__all__ = [
    "Benchmark",
    "BenchmarkComparator",
    "BenchmarkReporter",
    "BenchmarkSuite",
    "benchmark",
    "create_builtin_benchmarks",
    "run_benchmarks",
]
