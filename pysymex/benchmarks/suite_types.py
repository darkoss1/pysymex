"""Benchmarking suite types for pysymex.
Dataclasses and enums used by the benchmarking framework.
"""

from __future__ import annotations


from dataclasses import dataclass

from enum import Enum, auto

from typing import (
    Any,
)


class BenchmarkCategory(Enum):
    """Categories of benchmarks."""

    OPCODES = auto()

    PATHS = auto()

    SOLVING = auto()

    ANALYSIS = auto()

    END_TO_END = auto()

    MEMORY = auto()

    CONCURRENCY = auto()


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""

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

    iterations: int = 1

    warmup_iterations: int = 0

    timestamp: str = ""

    python_version: str = ""

    platform: str = ""

    @property
    def throughput(self) -> float:
        """Instructions per second."""

        if self.elapsed_seconds > 0:
            return self.instructions_executed / self.elapsed_seconds

        return 0.0

    @property
    def paths_per_second(self) -> float:
        """Paths explored per second."""

        if self.elapsed_seconds > 0:
            return self.paths_explored / self.elapsed_seconds

        return 0.0

    def to_dict(self) -> dict[str, Any]:
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
            "iterations": self.iterations,
            "throughput": self.throughput,
            "paths_per_second": self.paths_per_second,
            "timestamp": self.timestamp,
            "python_version": self.python_version,
            "platform": self.platform,
        }


@dataclass
class RegressionResult:
    """Result of comparing benchmarks for regressions."""

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


__all__ = [
    "BenchmarkCategory",
    "BenchmarkResult",
    "RegressionResult",
]
