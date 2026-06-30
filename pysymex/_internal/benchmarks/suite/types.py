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

"""Shared benchmark suite types.

This module owns benchmark metadata and result contracts used by the CLI,
runner, comparison, and reporting layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class BenchmarkCategory(Enum):
    """Categories of benchmarks.

    Used to group related benchmarks in reports and to filter
    specific workload types.
    """

    OPCODES = auto()
    PATHS = auto()
    SOLVING = auto()
    ANALYSIS = auto()
    END_TO_END = auto()
    MEMORY = auto()
    MODELS = auto()
    REPORTING = auto()
    SANDBOX = auto()
    CLI = auto()


class BenchmarkMode(Enum):
    """Supported benchmark run scales.

    ``QUICK`` is the default local loop, ``FULL`` covers all normal workloads,
    and ``STRESS`` is reserved for intentionally expensive cases.
    """

    QUICK = "quick"
    FULL = "full"
    STRESS = "stress"


class BenchmarkStatus(Enum):
    """Execution status for one benchmark case."""

    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Result of a single benchmark run.

    Attributes:
        name: Benchmark identifier.
        category: Workload category.
        elapsed_seconds: Total wall-clock time for all iterations.
        min_seconds: Fastest iteration.
        max_seconds: Slowest iteration.
        mean_seconds: Arithmetic mean across iterations.
        stddev_seconds: Standard deviation across iterations.
        peak_memory_mb: Peak traced memory in MB.
        allocated_mb: Mean allocated memory per iteration in MB.
        paths_explored: Symbolic-execution paths explored.
        instructions_executed: VM instructions executed.
        solver_calls: Number of Z3 solver invocations.
        solver_sat: Number of SAT solver outcomes.
        solver_unsat: Number of UNSAT solver outcomes.
        solver_unknown: Number of UNKNOWN solver outcomes.
        issue_count: Number of detector or scanner issues observed by the workload.
        iterations: Number of timing iterations.
        warmup_iterations: Number of discarded warm-up iterations.
        timestamp: ISO-8601 timestamp of the run.
        python_version: CPython version string.
        platform: OS/arch identifier.
        status: Execution status for the benchmark case.
        failure: Failure detail when the case did not complete.
        tags: Stable tags describing the benchmark concern.
        stability: Trust/stability note such as ``stable`` or ``machine-dependent``.

    """

    name: str
    category: BenchmarkCategory
    elapsed_seconds: float
    min_seconds: float = 0.0
    max_seconds: float = 0.0
    mean_seconds: float = 0.0
    stddev_seconds: float = 0.0
    peak_memory_mb: float = 0.0
    allocated_mb: float = 0.0
    paths_explored: int = 0
    instructions_executed: int = 0
    solver_calls: int = 0
    solver_sat: int = 0
    solver_unsat: int = 0
    solver_unknown: int = 0
    issue_count: int = 0
    iterations: int = 1
    warmup_iterations: int = 0
    timestamp: str = ""
    python_version: str = ""
    platform: str = ""
    status: BenchmarkStatus = BenchmarkStatus.COMPLETED
    failure: str | None = None
    tags: tuple[str, ...] = ()
    stability: str = "stable"

    @property
    def throughput(self) -> float:
        """Instructions per second."""
        if self.mean_seconds > 0:
            return self.instructions_executed / self.mean_seconds
        return 0.0

    @property
    def paths_per_second(self) -> float:
        """Paths explored per second."""
        if self.mean_seconds > 0:
            return self.paths_explored / self.mean_seconds
        return 0.0

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category.name,
            "elapsed_seconds": self.elapsed_seconds,
            "min_seconds": self.min_seconds,
            "max_seconds": self.max_seconds,
            "mean_seconds": self.mean_seconds,
            "stddev_seconds": self.stddev_seconds,
            "peak_memory_mb": self.peak_memory_mb,
            "allocated_mb": self.allocated_mb,
            "paths_explored": self.paths_explored,
            "instructions_executed": self.instructions_executed,
            "solver_calls": self.solver_calls,
            "solver_sat": self.solver_sat,
            "solver_unsat": self.solver_unsat,
            "solver_unknown": self.solver_unknown,
            "issue_count": self.issue_count,
            "iterations": self.iterations,
            "warmup_iterations": self.warmup_iterations,
            "throughput": self.throughput,
            "paths_per_second": self.paths_per_second,
            "timestamp": self.timestamp,
            "python_version": self.python_version,
            "platform": self.platform,
            "status": self.status.value,
            "failure": self.failure,
            "tags": list(self.tags),
            "stability": self.stability,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkEvent:
    """Live progress event emitted while a benchmark suite runs."""

    benchmark_name: str
    category: BenchmarkCategory
    phase: str
    completed: int
    total: int
    elapsed_seconds: float = 0.0
    message: str = ""


@dataclass(frozen=True, slots=True)
class RegressionResult:
    """Result of comparing a benchmark against its baseline.

    Attributes:
        benchmark_name: Name of the compared benchmark.
        baseline_mean: Mean time from the baseline run.
        current_mean: Mean time from the current run.
        change_percent: Percentage change (positive = slower).
        is_regression: ``True`` when *change_percent* exceeds the threshold.
        threshold_percent: Threshold used for the comparison.

    """

    benchmark_name: str
    baseline_mean: float
    current_mean: float
    change_percent: float
    is_regression: bool
    threshold_percent: float

    @property
    def change_description(self) -> str:
        """Human-readable change description."""
        direction = "slower" if self.change_percent > 0 else "faster"
        return f"{abs(self.change_percent):.1f}% {direction}"
