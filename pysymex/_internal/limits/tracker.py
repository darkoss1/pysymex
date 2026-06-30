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

"""Host engine limit usage tracker."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from pysymex._internal.limits.models import (
    AnalysisTimeoutError,
    LimitExceeded,
    ResourceLimits,
    ResourceSnapshot,
    ResourceType,
)
from pysymex._internal.limits.platform import current_memory_usage_mb
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


class ResourceTracker:
    """Central monitor for system resources and analysis depth."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        """Initialize the resource usage tracker.

        Args:
            limits (ResourceLimits | None): Configurable resource limits. If None, defaults to default ResourceLimits.

        """
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
        self.warning_callbacks: list[Callable[[ResourceType, object, object], None]] = []
        self._warnings_issued: set[ResourceType] = set()
        self._degraded: bool = False
        self._memory_baseline_mb: float = 0.0
        self._memory_sum_mb: float = 0.0
        self._memory_samples: int = 0
        self.lock = threading.RLock()

    def start(self) -> None:
        """Start resource tracking."""
        self._start_time = time.perf_counter()
        self._reset_counters()
        self._memory_baseline_mb = self.memory_usage_mb
        self._record_memory_sample(self._memory_baseline_mb)

    def reset(self) -> None:
        """Reset for a new analysis unit while keeping limits."""
        self._reset_counters()
        self._start_time = None
        self._memory_baseline_mb = 0.0

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
        self._memory_sum_mb = 0.0
        self._memory_samples = 0

    def snapshot(self) -> ResourceSnapshot:
        """Get current resource usage snapshot."""
        with self.lock:
            avg_mem = (
                self._memory_sum_mb / self._memory_samples if self._memory_samples > 0 else 0.0
            )
            return ResourceSnapshot(
                paths_explored=self._paths_explored,
                current_depth=self._current_depth,
                max_depth_reached=self._max_depth_reached,
                iterations=self._iterations,
                elapsed_time=self.elapsed_time,
                memory_mb=self.memory_usage_mb,
                avg_memory_mb=avg_mem,
                constraint_count=self._constraint_count,
                solver_calls=self._solver_calls,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
            )

    def _record_memory_sample(self, memory_mb: float | None = None) -> None:
        """Record a memory usage sample for average calculation."""
        mem = memory_mb if memory_mb is not None else self.memory_usage_mb
        if mem > 0:
            with self.lock:
                self._memory_sum_mb += mem
                self._memory_samples += 1

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        if self._start_time is None:
            return 0.0
        return time.perf_counter() - self._start_time

    @property
    def memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        return current_memory_usage_mb(logger)

    @property
    def is_degraded(self) -> bool:
        """Check if analysis is in degraded mode."""
        return self._degraded

    def add_warning_callback(
        self,
        callback: Callable[[ResourceType, object, object], None],
    ) -> None:
        """Add a callback for soft limit warnings."""
        self.warning_callbacks.append(callback)

    def _check_soft_limit(
        self,
        resource_type: ResourceType,
        current: object,
        limit: object,
        ratio: float,
    ) -> None:
        """Check and warn for soft limits."""
        if resource_type in self._warnings_issued:
            return
        if not isinstance(limit, (int, float)) or not isinstance(current, (int, float)):
            return
        threshold = limit * ratio
        if current >= threshold:
            self._warnings_issued.add(resource_type)
            for callback in self.warning_callbacks:
                try:
                    callback(resource_type, current, limit)
                except Exception:
                    logger.debug("Warning callback failed for %s", resource_type, exc_info=True)

    def check_path_limit(self) -> None:
        """Check the elective path limit when one is configured."""
        with self.lock:
            limit = self.limits.max_paths
            if limit is None:
                return
            if self._paths_explored >= limit:
                raise LimitExceeded(ResourceType.PATHS, self._paths_explored, limit)
            self._check_soft_limit(
                ResourceType.PATHS,
                self._paths_explored,
                limit,
                self.limits.soft_path_ratio,
            )

    def check_depth_limit(self) -> None:
        """Check if the current path depth exceeds the maximum configured depth limit.

        Raises:
            LimitExceeded: If the current path depth reaches or exceeds the configured limit.

        """
        with self.lock:
            limit = self.limits.max_depth
            if limit is not None and self._current_depth >= limit:
                raise LimitExceeded(ResourceType.DEPTH, self._current_depth, limit)

    def check_iteration_limit(self) -> None:
        """Check if the total execution iteration count exceeds the maximum configured iteration limit.

        Raises:
            LimitExceeded: If the number of iterations reaches or exceeds the configured limit.

        """
        with self.lock:
            limit = self.limits.max_iterations
            if limit is not None and self._iterations >= limit:
                raise LimitExceeded(
                    ResourceType.ITERATIONS,
                    self._iterations,
                    limit,
                )

    def check_time_limit(self) -> None:
        """Check time limit."""
        limit = self.limits.timeout_seconds
        if limit is None:
            return
        elapsed = self.elapsed_time
        if elapsed >= limit:
            raise AnalysisTimeoutError(elapsed, limit)
        self._check_soft_limit(
            ResourceType.TIME,
            elapsed,
            limit,
            self.limits.soft_time_ratio,
        )

    def check_memory_limit(self) -> None:
        """Check the elective host memory-growth limit when configured."""
        limit = self.limits.max_memory_mb
        if limit is None:
            return
        memory_mb = self.memory_usage_mb
        if memory_mb <= 0:
            return
        self._record_memory_sample()
        baseline_mb = self._memory_baseline_mb if self._memory_baseline_mb > 0 else memory_mb
        growth_mb = max(0.0, memory_mb - baseline_mb)
        if growth_mb >= limit:
            raise LimitExceeded(ResourceType.MEMORY, growth_mb, limit)

    def check_all_limits(self) -> None:
        """Check all resource limits."""
        iters = self._iterations
        max_depth = self.limits.max_depth
        if max_depth is not None and self._current_depth >= max_depth:
            raise LimitExceeded(ResourceType.DEPTH, self._current_depth, max_depth)
        max_iterations = self.limits.max_iterations
        if max_iterations is not None and iters >= max_iterations:
            raise LimitExceeded(ResourceType.ITERATIONS, iters, max_iterations)
        max_paths = self.limits.max_paths
        if max_paths is not None and self._paths_explored >= max_paths:
            raise LimitExceeded(ResourceType.PATHS, self._paths_explored, max_paths)
        self.check_time_limit()
        if iters & 255 == 0:
            self.check_memory_limit()

    def record_path(self) -> int:
        """Record a path explored and return the count."""
        self._paths_explored += 1
        return self._paths_explored

    def record_iteration(self) -> int:
        """Record an iteration and return the count."""
        self._iterations += 1
        return self._iterations

    def push_depth(self) -> int:
        """Push call depth and return new depth."""
        with self.lock:
            self._current_depth += 1
            self._max_depth_reached = max(self._max_depth_reached, self._current_depth)
            return self._current_depth

    def pop_depth(self) -> int:
        """Pop call depth and return new depth."""
        with self.lock:
            self._current_depth = max(0, self._current_depth - 1)
            return self._current_depth

    def record_constraint(self, count: int = 1) -> None:
        """Record constraint additions."""
        with self.lock:
            self._constraint_count += count

    def record_solver_call(self, cache_hit: bool = False) -> None:
        """Record a solver call."""
        with self.lock:
            self._solver_calls += 1
            if cache_hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1

    def enter_degraded_mode(self, reason: str) -> None:
        """Enter degraded mode for graceful degradation."""
        _ = reason
        with self.lock:
            self._degraded = True

    def get_progress(self) -> dict[str, float]:
        """Return configured-limit utilization percentages.

        Automatic limits report ``0.0`` because they have no finite denominator.
        """
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
