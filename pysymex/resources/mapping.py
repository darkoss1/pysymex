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

"""Map profile and executor settings to :class:`~pysymex.resources.models.ResourceLimits`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.config.defaults import (
    DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE,
    DEFAULT_LIMIT_MAX_LIST_LENGTH,
    DEFAULT_LIMIT_MAX_MEMORY_MB,
    DEFAULT_LIMIT_MAX_STRING_LENGTH,
)
from pysymex.resources.models import ResourceLimits

if TYPE_CHECKING:
    from pysymex.config.sections import AnalysisLimits
    from pysymex.execution.config.settings import ExecutionConfig

__all__ = [
    "analysis_limits_from_resource_limits",
    "resource_limits_from_analysis_limits",
    "resource_limits_from_execution_config",
]


def resource_limits_from_analysis_limits(limits: AnalysisLimits) -> ResourceLimits:
    """Build engine :class:`ResourceLimits` from a TOML/profile :class:`AnalysisLimits`."""
    return ResourceLimits(
        max_paths=limits.max_paths,
        max_depth=limits.max_depth,
        max_iterations=limits.max_iterations,
        timeout_seconds=limits.timeout_seconds,
        max_memory_mb=limits.max_memory_mb,
        max_constraints=limits.max_constraint_size,
    )


def analysis_limits_from_resource_limits(
    limits: ResourceLimits,
    *,
    max_string_length: int = DEFAULT_LIMIT_MAX_STRING_LENGTH,
    max_list_length: int = DEFAULT_LIMIT_MAX_LIST_LENGTH,
) -> AnalysisLimits:
    """Build profile :class:`AnalysisLimits` from engine limits plus serialization-only caps."""
    from pysymex.config.sections import AnalysisLimits

    return AnalysisLimits(
        max_paths=limits.max_paths,
        max_depth=limits.max_depth,
        max_iterations=limits.max_iterations,
        timeout_seconds=limits.timeout_seconds,
        max_memory_mb=limits.max_memory_mb,
        max_constraint_size=limits.max_constraints,
        max_string_length=max_string_length,
        max_list_length=max_list_length,
    )


def resource_limits_from_execution_config(config: ExecutionConfig) -> ResourceLimits:
    """Build :class:`ResourceLimits` for :class:`~pysymex.resources.tracker.ResourceTracker`."""
    return ResourceLimits(
        max_paths=config.max_paths,
        max_depth=config.max_depth,
        max_iterations=config.max_iterations,
        timeout_seconds=config.timeout_seconds,
        max_memory_mb=DEFAULT_LIMIT_MAX_MEMORY_MB,
        max_constraints=DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE,
    )
