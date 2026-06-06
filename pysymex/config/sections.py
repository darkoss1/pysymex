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

"""Configuration section dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.resources.models import ResourceLimits

from pysymex.config.defaults import (
    DEFAULT_ANALYSIS_ARRAY_SIZE_LIMIT,
    DEFAULT_ANALYSIS_CONSTRAINT_CACHING,
    DEFAULT_ANALYSIS_EXCLUDE_PATTERNS,
    DEFAULT_ANALYSIS_INCREMENTAL_SOLVING,
    DEFAULT_ANALYSIS_INCLUDE_PATTERNS,
    DEFAULT_ANALYSIS_LOOP_UNROLL_LIMIT,
    DEFAULT_ANALYSIS_STRATEGY,
    DEFAULT_ANALYSIS_STRING_SOLVER,
    DEFAULT_CONCURRENCY_ASYNC_ANALYSIS,
    DEFAULT_CONCURRENCY_DETECT_DEADLOCKS,
    DEFAULT_CONCURRENCY_DETECT_RACES,
    DEFAULT_CONCURRENCY_DPOR_ENABLED,
    DEFAULT_CONCURRENCY_ENABLED,
    DEFAULT_CONCURRENCY_LOCKSET_ANALYSIS,
    DEFAULT_CONCURRENCY_MAX_INTERLEAVINGS,
    DEFAULT_DETECT_ASSERTION_ERRORS,
    DEFAULT_DETECT_ATTRIBUTE_ERRORS,
    DEFAULT_DETECT_DIVISION_BY_ZERO,
    DEFAULT_DETECT_INDEX_ERRORS,
    DEFAULT_DETECT_KEY_ERRORS,
    DEFAULT_DETECT_NULL_POINTER,
    DEFAULT_DETECT_OVERFLOW,
    DEFAULT_DETECT_TYPE_ERRORS,
    DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE,
    DEFAULT_LIMIT_MAX_DEPTH,
    DEFAULT_LIMIT_MAX_ITERATIONS,
    DEFAULT_LIMIT_MAX_LIST_LENGTH,
    DEFAULT_LIMIT_MAX_MEMORY_MB,
    DEFAULT_LIMIT_MAX_PATHS,
    DEFAULT_LIMIT_MAX_STRING_LENGTH,
    DEFAULT_LIMIT_TIMEOUT_SECONDS,
    DEFAULT_OUTPUT_COLOR,
    DEFAULT_OUTPUT_FORMAT,
    DEFAULT_OUTPUT_QUIET,
    DEFAULT_OUTPUT_SHOW_CONSTRAINTS,
    DEFAULT_OUTPUT_SHOW_PATHS,
    DEFAULT_OUTPUT_SHOW_TIMING,
    DEFAULT_OUTPUT_VERBOSE,
    DEFAULT_SOLVER_CACHE_SIZE,
    DEFAULT_SOLVER_COMPACTION_INTERVAL,
    DEFAULT_SOLVER_LAZY_EVAL_THRESHOLD,
    DEFAULT_SOLVER_PORTFOLIO_TIMEOUT_MS,
    DEFAULT_SOLVER_SIMPLIFY_CONSTRAINTS,
    DEFAULT_SOLVER_STRATEGY,
    DEFAULT_SOLVER_TIMEOUT_MS,
    DEFAULT_SOLVER_WARM_START,
)


@dataclass(frozen=True, slots=True)
class SolverConfig:
    """Configuration for the Z3 solver subsystem."""

    strategy: str = DEFAULT_SOLVER_STRATEGY
    cache_size: int = DEFAULT_SOLVER_CACHE_SIZE
    lazy_eval_threshold: int = DEFAULT_SOLVER_LAZY_EVAL_THRESHOLD
    compaction_interval: int = DEFAULT_SOLVER_COMPACTION_INTERVAL
    portfolio_timeout_ms: int = DEFAULT_SOLVER_PORTFOLIO_TIMEOUT_MS
    warm_start: bool = DEFAULT_SOLVER_WARM_START
    simplify_constraints: bool = DEFAULT_SOLVER_SIMPLIFY_CONSTRAINTS
    solver_timeout_ms: int = DEFAULT_SOLVER_TIMEOUT_MS

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "strategy": self.strategy,
            "cache_size": self.cache_size,
            "lazy_eval_threshold": self.lazy_eval_threshold,
            "compaction_interval": self.compaction_interval,
            "portfolio_timeout_ms": self.portfolio_timeout_ms,
            "warm_start": self.warm_start,
            "simplify_constraints": self.simplify_constraints,
            "solver_timeout_ms": self.solver_timeout_ms,
        }


@dataclass(frozen=True, slots=True)
class ConcurrencyConfig:
    """Configuration for concurrency and async analysis."""

    enabled: bool = DEFAULT_CONCURRENCY_ENABLED
    detect_races: bool = DEFAULT_CONCURRENCY_DETECT_RACES
    detect_deadlocks: bool = DEFAULT_CONCURRENCY_DETECT_DEADLOCKS
    async_analysis: bool = DEFAULT_CONCURRENCY_ASYNC_ANALYSIS
    max_interleavings: int = DEFAULT_CONCURRENCY_MAX_INTERLEAVINGS
    dpor_enabled: bool = DEFAULT_CONCURRENCY_DPOR_ENABLED
    lockset_analysis: bool = DEFAULT_CONCURRENCY_LOCKSET_ANALYSIS

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "enabled": self.enabled,
            "detect_races": self.detect_races,
            "detect_deadlocks": self.detect_deadlocks,
            "async_analysis": self.async_analysis,
            "max_interleavings": self.max_interleavings,
            "dpor_enabled": self.dpor_enabled,
            "lockset_analysis": self.lockset_analysis,
        }


@dataclass
class DetectorConfig:
    """Configuration for bug detectors."""

    division_by_zero: bool = DEFAULT_DETECT_DIVISION_BY_ZERO
    assertion_errors: bool = DEFAULT_DETECT_ASSERTION_ERRORS
    index_errors: bool = DEFAULT_DETECT_INDEX_ERRORS
    type_errors: bool = DEFAULT_DETECT_TYPE_ERRORS
    key_errors: bool = DEFAULT_DETECT_KEY_ERRORS
    attribute_errors: bool = DEFAULT_DETECT_ATTRIBUTE_ERRORS
    overflow: bool = DEFAULT_DETECT_OVERFLOW
    null_pointer: bool = DEFAULT_DETECT_NULL_POINTER

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "division_by_zero": self.division_by_zero,
            "assertion_errors": self.assertion_errors,
            "index_errors": self.index_errors,
            "type_errors": self.type_errors,
            "key_errors": self.key_errors,
            "attribute_errors": self.attribute_errors,
            "overflow": self.overflow,
            "null_pointer": self.null_pointer,
        }


@dataclass
class AnalysisLimits:
    """Resource limits for project files (``[tool.pysymex.limits]``).

    Runtime enforcement uses :class:`~pysymex.resources.models.ResourceLimits`
    via :meth:`to_resource_limits` or :func:`~pysymex.resources.mapping.resource_limits_from_analysis_limits`.
    Extra fields (``max_string_length``, ``max_list_length``) are profile-only caps.
    """

    max_paths: int = DEFAULT_LIMIT_MAX_PATHS
    max_depth: int = DEFAULT_LIMIT_MAX_DEPTH
    max_iterations: int = DEFAULT_LIMIT_MAX_ITERATIONS
    timeout_seconds: float = DEFAULT_LIMIT_TIMEOUT_SECONDS
    max_memory_mb: int = DEFAULT_LIMIT_MAX_MEMORY_MB
    max_constraint_size: int = DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE
    max_string_length: int = DEFAULT_LIMIT_MAX_STRING_LENGTH
    max_list_length: int = DEFAULT_LIMIT_MAX_LIST_LENGTH

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "max_paths": self.max_paths,
            "max_depth": self.max_depth,
            "max_iterations": self.max_iterations,
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_constraint_size": self.max_constraint_size,
            "max_string_length": self.max_string_length,
            "max_list_length": self.max_list_length,
        }

    def to_resource_limits(self) -> ResourceLimits:
        """Return engine limits for :class:`~pysymex.resources.tracker.ResourceTracker`."""
        from pysymex.resources.mapping import resource_limits_from_analysis_limits

        return resource_limits_from_analysis_limits(self)


@dataclass
class OutputConfig:
    """Configuration for output and reporting."""

    format: str = DEFAULT_OUTPUT_FORMAT
    output_dir: str | None = None
    color: bool = DEFAULT_OUTPUT_COLOR
    verbose: bool = DEFAULT_OUTPUT_VERBOSE
    quiet: bool = DEFAULT_OUTPUT_QUIET
    show_paths: bool = DEFAULT_OUTPUT_SHOW_PATHS
    show_constraints: bool = DEFAULT_OUTPUT_SHOW_CONSTRAINTS
    show_timing: bool = DEFAULT_OUTPUT_SHOW_TIMING

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "format": self.format,
            "output_dir": self.output_dir,
            "color": self.color,
            "verbose": self.verbose,
            "quiet": self.quiet,
            "show_paths": self.show_paths,
            "show_constraints": self.show_constraints,
            "show_timing": self.show_timing,
        }


@dataclass
class AnalysisConfig:
    """Configuration for analysis behaviour."""

    strategy: str = DEFAULT_ANALYSIS_STRATEGY
    loop_unroll_limit: int = DEFAULT_ANALYSIS_LOOP_UNROLL_LIMIT
    array_size_limit: int = DEFAULT_ANALYSIS_ARRAY_SIZE_LIMIT
    string_solver: str = DEFAULT_ANALYSIS_STRING_SOLVER
    incremental_solving: bool = DEFAULT_ANALYSIS_INCREMENTAL_SOLVING
    constraint_caching: bool = DEFAULT_ANALYSIS_CONSTRAINT_CACHING
    include_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_ANALYSIS_INCLUDE_PATTERNS)
    )
    exclude_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_ANALYSIS_EXCLUDE_PATTERNS)
    )

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "strategy": self.strategy,
            "loop_unroll_limit": self.loop_unroll_limit,
            "array_size_limit": self.array_size_limit,
            "string_solver": self.string_solver,
            "incremental_solving": self.incremental_solving,
            "constraint_caching": self.constraint_caching,
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
        }
