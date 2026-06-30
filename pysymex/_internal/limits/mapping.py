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

"""Map executor settings to :class:`~pysymex._internal.limits.models.ResourceLimits`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.limits.models import ResourceLimits

if TYPE_CHECKING:
    from pysymex._internal.config.execution.settings import ExecutionConfig


def limits_from_execution_config(config: ExecutionConfig) -> ResourceLimits:
    """Build :class:`ResourceLimits` for :class:`~pysymex._internal.limits.tracker.ResourceTracker`."""
    return ResourceLimits(
        max_paths=config.max_paths,
        max_depth=config.max_depth,
        max_iterations=config.max_iterations,
        timeout_seconds=config.timeout_seconds,
        max_memory_mb=None,
        max_constraints=None,
    )
