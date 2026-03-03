"""Resource management and limits for pysymex.
Provides resource tracking, limits enforcement, and graceful degradation.
"""

from __future__ import annotations


import logging

import signal

import sys

import threading

import time

from collections.abc import Callable

from contextlib import contextmanager

from dataclasses import dataclass, field

from enum import Enum, auto

from typing import Any

logger = logging.getLogger(__name__)


if sys.platform != "win32":
    import resource as sys_resource

else:
    sys_resource = None


class ResourceType(Enum):
    """Types of resources to track."""

    PATHS = auto()

    DEPTH = auto()

    ITERATIONS = auto()

    TIME = auto()

    MEMORY = auto()

    CONSTRAINTS = auto()


class LimitExceeded(Exception):
    """Exception raised when a resource limit is exceeded."""

    def __init__(self, resource_type: ResourceType, current: Any, limit: Any):
        self.resource_type = resource_type

        self.current = current

        self.limit = limit

        super().__init__(f"{resource_type.name} limit exceeded: {current} >= {limit}")


class TimeoutError(LimitExceeded):
    """Exception raised when analysis times out."""

    def __init__(self, elapsed: float, limit: float):
        super().__init__(ResourceType.TIME, elapsed, limit)


@dataclass
class ResourceSnapshot:
    """Snapshot of current resource usage."""

    paths_explored: int = 0

    current_depth: int = 0

    max_depth_reached: int = 0

    iterations: int = 0

    elapsed_time: float = 0.0

    memory_mb: float = 0.0

    constraint_count: int = 0

    solver_calls: int = 0

    cache_hits: int = 0

    cache_misses: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "paths_explored": self.paths_explored,
            "current_depth": self.current_depth,
            "max_depth_reached": self.max_depth_reached,
            "iterations": self.iterations,
            "elapsed_time": self.elapsed_time,
            "memory_mb": self.memory_mb,
            "constraint_count": self.constraint_count,
            "solver_calls": self.solver_calls,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }


@dataclass
class ResourceLimits:
    """Configurable resource limits."""

    max_paths: int = 1000

    max_depth: int = 100

    max_iterations: int = 10000

    timeout_seconds: float = 60.0

    max_memory_mb: int = 1024

    max_constraints: int = 10000

    soft_path_ratio: float = 0.8

    soft_time_ratio: float = 0.9

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "max_paths": self.max_paths,
            "max_depth": self.max_depth,
            "max_iterations": self.max_iterations,
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_constraints": self.max_constraints,
            "soft_path_ratio": self.soft_path_ratio,
            "soft_time_ratio": self.soft_time_ratio,
        }


class ResourceTracker:
    """Tracks and enforces resource limits during analysis.
    Provides:
    - Resource usage tracking
    - Limit enforcement with exceptions
    - Soft limit warnings
    - Graceful degradation support
    """

    def __init__(self, limits: ResourceLimits | None = None):
        self.limits = limits or ResourceLimits()

        self._paths_explored: int = 0

        self._current_depth: int = 0

        self._max_depth_reached: int = 0

        self._iterations: int = 0

        self._start_time: float | None = None

        self._constraint_count: int = 0

        self._solver_calls: int = 0

        self._cache_hits: int = 0

        self._cache_misses: int = 0

        self._warning_callbacks: list[Callable[[ResourceType, Any, Any], None]] = []

        self._warnings_issued: set[ResourceType] = set()

        self._degraded: bool = False

        self._degradation_reason: str | None = None

        self._lock = threading.RLock()

    def start(self) -> None:
        """Start resource tracking."""

        self._start_time = time.perf_counter()

        self._reset_counters()

    def reset(self) -> None:
        """Reset for a new analysis unit while keeping limits."""

        self._reset_counters()

        self._start_time = None

    def _reset_counters(self) -> None:
        """Reset all counters."""

        self._paths_explored = 0

        self._current_depth = 0

        self._max_depth_reached = 0

        self._iterations = 0

        self._constraint_count = 0

        self._solver_calls = 0

        self._cache_hits = 0

        self._cache_misses = 0

        self._warnings_issued.clear()

        self._degraded = False

        self._degradation_reason = None

    def snapshot(self) -> ResourceSnapshot:
        """Get current resource usage snapshot."""

        with self._lock:
            return ResourceSnapshot(
                paths_explored=self._paths_explored,
                current_depth=self._current_depth,
                max_depth_reached=self._max_depth_reached,
                iterations=self._iterations,
                elapsed_time=self.elapsed_time,
                memory_mb=self.memory_usage_mb,
                constraint_count=self._constraint_count,
                solver_calls=self._solver_calls,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
            )

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""

        if self._start_time is None:
            return 0.0

        return time.perf_counter() - self._start_time

    @property
    def memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""

        try:
            if sys.platform != "win32":
                usage = sys_resource.getrusage(sys_resource.RUSAGE_SELF)

                return usage.ru_maxrss / 1024

            else:
                try:
                    import psutil

                    process = psutil.Process()

                    return process.memory_info().rss / (1024 * 1024)

                except ImportError:
                    return 0.0

        except Exception:
            logger.debug("Failed to get peak memory usage", exc_info=True)

            return 0.0

    @property
    def is_degraded(self) -> bool:
        """Check if analysis is in degraded mode."""

        return self._degraded

    def add_warning_callback(
        self,
        callback: Callable[[ResourceType, Any, Any], None],
    ) -> None:
        """Add a callback for soft limit warnings."""

        self._warning_callbacks.append(callback)

    def _check_soft_limit(
        self,
        resource_type: ResourceType,
        current: Any,
        limit: Any,
        ratio: float,
    ) -> None:
        """Check and warn for soft limits."""

        if resource_type in self._warnings_issued:
            return

        threshold = limit * ratio

        if current >= threshold:
            self._warnings_issued.add(resource_type)

            for callback in self._warning_callbacks:
                try:
                    callback(resource_type, current, limit)

                except Exception:
                    logger.debug("Warning callback failed for %s", resource_type, exc_info=True)

    def check_path_limit(self) -> None:
        """Check path count limit."""

        with self._lock:
            if self._paths_explored >= self.limits.max_paths:
                raise LimitExceeded(
                    ResourceType.PATHS,
                    self._paths_explored,
                    self.limits.max_paths,
                )

            self._check_soft_limit(
                ResourceType.PATHS,
                self._paths_explored,
                self.limits.max_paths,
                self.limits.soft_path_ratio,
            )

    def check_depth_limit(self) -> None:
        """Check depth limit."""

        with self._lock:
            if self._current_depth >= self.limits.max_depth:
                raise LimitExceeded(
                    ResourceType.DEPTH,
                    self._current_depth,
                    self.limits.max_depth,
                )

    def check_iteration_limit(self) -> None:
        """Check iteration limit."""

        with self._lock:
            if self._iterations >= self.limits.max_iterations:
                raise LimitExceeded(
                    ResourceType.ITERATIONS,
                    self._iterations,
                    self.limits.max_iterations,
                )

    def check_time_limit(self) -> None:
        """Check time limit."""

        elapsed = self.elapsed_time

        if elapsed >= self.limits.timeout_seconds:
            raise TimeoutError(elapsed, self.limits.timeout_seconds)

        self._check_soft_limit(
            ResourceType.TIME,
            elapsed,
            self.limits.timeout_seconds,
            self.limits.soft_time_ratio,
        )

    def check_memory_limit(self) -> None:
        """Check memory limit."""

        memory_mb = self.memory_usage_mb

        if memory_mb > 0 and memory_mb >= self.limits.max_memory_mb:
            raise LimitExceeded(
                ResourceType.MEMORY,
                memory_mb,
                self.limits.max_memory_mb,
            )

    def check_all_limits(self) -> None:
        """Check all resource limits.

        Time and memory checks are throttled to reduce overhead:
        - Time: every 32 iterations (perf_counter is cheap but adds up)
        - Memory: every 256 iterations (psutil is expensive on Windows)
        - Path/depth/iteration: every call (fast integer comparisons)
        """

        iters = self._iterations

        if self._current_depth >= self.limits.max_depth:
            raise LimitExceeded(ResourceType.DEPTH, self._current_depth, self.limits.max_depth)

        if iters >= self.limits.max_iterations:
            raise LimitExceeded(ResourceType.ITERATIONS, iters, self.limits.max_iterations)

        if self._paths_explored >= self.limits.max_paths:
            raise LimitExceeded(ResourceType.PATHS, self._paths_explored, self.limits.max_paths)

        if iters & 31 == 0:
            self.check_time_limit()

        if iters & 255 == 0:
            self.check_memory_limit()

    def record_path(self) -> int:
        """Record a path explored and return the count.

        Lock-free for the common single-threaded case.
        """

        self._paths_explored += 1

        return self._paths_explored

    def record_iteration(self) -> int:
        """Record an iteration and return the count.

        Lock-free for the common single-threaded case.
        """

        self._iterations += 1

        return self._iterations

    def push_depth(self) -> int:
        """Push call depth and return new depth."""

        with self._lock:
            self._current_depth += 1

            self._max_depth_reached = max(
                self._max_depth_reached,
                self._current_depth,
            )

            return self._current_depth

    def pop_depth(self) -> int:
        """Pop call depth and return new depth."""

        with self._lock:
            self._current_depth = max(0, self._current_depth - 1)

            return self._current_depth

    def record_constraint(self, count: int = 1) -> None:
        """Record constraint additions."""

        with self._lock:
            self._constraint_count += count

    def record_solver_call(self, cache_hit: bool = False) -> None:
        """Record a solver call."""

        with self._lock:
            self._solver_calls += 1

            if cache_hit:
                self._cache_hits += 1

            else:
                self._cache_misses += 1

    def enter_degraded_mode(self, reason: str) -> None:
        """Enter degraded mode for graceful degradation."""

        with self._lock:
            self._degraded = True

            self._degradation_reason = reason

    def get_progress(self) -> dict[str, float]:
        """Get progress indicators as percentages."""

        return {
            "paths": (
                (self._paths_explored / self.limits.max_paths * 100) if self.limits.max_paths else 0
            ),
            "depth": (
                (self._max_depth_reached / self.limits.max_depth * 100)
                if self.limits.max_depth
                else 0
            ),
            "iterations": (
                (self._iterations / self.limits.max_iterations * 100)
                if self.limits.max_iterations
                else 0
            ),
            "time": (
                (self.elapsed_time / self.limits.timeout_seconds * 100)
                if self.limits.timeout_seconds
                else 0
            ),
        }


@contextmanager
def timeout_context(seconds: float, message: str = "Operation timed out"):
    """Context manager that raises TimeoutError after specified seconds.
    Note: Only works on Unix-like systems with SIGALRM.
    On Windows, this is a no-op.
    """

    if sys.platform == "win32":
        yield

        return

    def handler(_signum, frame):
        raise TimeoutError(seconds, seconds)

    old_handler = signal.signal(signal.SIGALRM, handler)

    signal.setitimer(signal.ITIMER_REAL, seconds)

    try:
        yield

    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

        signal.signal(signal.SIGALRM, old_handler)


class GracefulDegradation:
    """Manages graceful degradation when limits are approached.
    Strategies:
    - Reduce path exploration (increase pruning)
    - Skip complex constraints
    - Use approximations
    - Return partial results
    """

    def __init__(self, tracker: ResourceTracker):
        self.tracker = tracker

        self._strategies: list[str] = []

    def should_skip_path(self, path_complexity: int) -> bool:
        """Check if a path should be skipped for degradation."""

        if not self.tracker.is_degraded:
            return False

        return path_complexity > 10

    def should_approximate_constraint(self) -> bool:
        """Check if constraints should be approximated."""

        progress = self.tracker.get_progress()

        return progress["time"] > 90 or progress["paths"] > 95

    def should_stop_early(self) -> bool:
        """Check if analysis should stop early."""

        try:
            self.tracker.check_all_limits()

            return False

        except LimitExceeded:
            return True

    def get_active_strategies(self) -> list[str]:
        """Get list of active degradation strategies."""

        return list(self._strategies)

    def activate_strategy(self, strategy: str) -> None:
        """Activate a degradation strategy."""

        if strategy not in self._strategies:
            self._strategies.append(strategy)


@dataclass
class PartialResult:
    """Represents a partial result from interrupted analysis."""

    completed: bool = False

    reason: str | None = None

    paths_completed: int = 0

    paths_remaining_estimate: int = 0

    issues_found: list[Any] = field(default_factory=lambda: list[Any]())

    warnings: list[str] = field(default_factory=lambda: list[str]())

    resource_snapshot: ResourceSnapshot | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "completed": self.completed,
            "reason": self.reason,
            "paths_completed": self.paths_completed,
            "paths_remaining_estimate": self.paths_remaining_estimate,
            "issues_found": len(self.issues_found),
            "warnings": self.warnings,
            "resources": self.resource_snapshot.to_dict() if self.resource_snapshot else None,
        }


def create_partial_result(
    tracker: ResourceTracker,
    issues: list[Any],
    error: Exception | None = None,
) -> PartialResult:
    """Create a partial result from current state."""

    snap = tracker.snapshot()

    result = PartialResult(
        completed=error is None,
        paths_completed=snap.paths_explored,
        issues_found=issues,
        resource_snapshot=snap,
    )

    if error:
        if isinstance(error, LimitExceeded):
            result.reason = f"Limit exceeded: {error.resource_type.name}"

        else:
            result.reason = str(error)

    return result


__all__ = [
    "ResourceType",
    "LimitExceeded",
    "TimeoutError",
    "ResourceSnapshot",
    "ResourceLimits",
    "ResourceTracker",
    "timeout_context",
    "GracefulDegradation",
    "PartialResult",
    "create_partial_result",
]
