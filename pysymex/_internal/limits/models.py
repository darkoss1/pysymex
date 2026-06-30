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

"""Resource limit domain models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from pysymex._internal.config.defaults import (
    DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE,
    DEFAULT_LIMIT_MAX_MEMORY_MB,
)


class ResourceType(Enum):
    """Enumeration of trackable resource categories."""

    PATHS = auto()
    DEPTH = auto()
    ITERATIONS = auto()
    TIME = auto()
    MEMORY = auto()
    CONSTRAINTS = auto()


class LimitExceeded(Exception):
    """Raised when an elective or mandatory resource limit is reached during analysis."""

    def __init__(self, resource_type: ResourceType, current: object, limit: object) -> None:
        """Initialize the limit violation record and format the error message."""
        self.resource_type = resource_type
        self.current = current
        self.limit = limit
        super().__init__(f"{resource_type.name} limit exceeded: {current} >= {limit}")


class AnalysisTimeoutError(LimitExceeded):
    """Raised when analysis exceeds its wall-clock timeout."""

    def __init__(self, elapsed: float, limit: float) -> None:
        """Initialize the analysis timeout error with elapsed time and timeout limit.

        Args:
            elapsed (float): The actual elapsed time in seconds.
            limit (float): The configured timeout limit in seconds.

        """
        super().__init__(ResourceType.TIME, elapsed, limit)


TimeoutError = AnalysisTimeoutError


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """Point-in-time snapshot of resource usage."""

    paths_explored: int = 0
    current_depth: int = 0
    max_depth_reached: int = 0
    iterations: int = 0
    elapsed_time: float = 0.0
    memory_mb: float = 0.0
    avg_memory_mb: float = 0.0
    constraint_count: int = 0
    solver_calls: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "paths_explored": self.paths_explored,
            "current_depth": self.current_depth,
            "max_depth_reached": self.max_depth_reached,
            "iterations": self.iterations,
            "elapsed_time": self.elapsed_time,
            "memory_mb": self.memory_mb,
            "avg_memory_mb": self.avg_memory_mb,
            "constraint_count": self.constraint_count,
            "solver_calls": self.solver_calls,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        }


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Host engine limits enforced by :class:`~pysymex._internal.limits.tracker.ResourceTracker`.

    Runtime callers build these from direct execution configuration or sandbox
    policy, not from the removed TOML/profile config graph.
    """

    max_paths: int | None = None
    max_depth: int | None = None
    max_iterations: int | None = None
    timeout_seconds: float | None = None
    max_memory_mb: int | None = DEFAULT_LIMIT_MAX_MEMORY_MB
    max_constraints: int | None = DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE
    soft_path_ratio: float = 0.8
    soft_time_ratio: float = 0.9

    def to_dict(self) -> dict[str, object]:
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
