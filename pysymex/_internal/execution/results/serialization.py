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

"""Dictionary serialization for execution results."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.results.result import ExecutionResult


def execution_result_to_dict(result: ExecutionResult) -> dict[str, object]:
    """Return the stable dictionary summary for an execution result."""
    return {
        "function_name": result.function_name,
        "source_file": result.source_file,
        "paths_explored": result.paths_explored,
        "paths_completed": result.paths_completed,
        "paths_pruned": result.paths_pruned,
        "coverage_size": len(result.coverage),
        "total_time_seconds": result.total_time_seconds,
        "avg_memory_mb": result.avg_memory_mb,
        "degraded_passes": list(result.degraded_passes),
        "outcome_evidence": [event.to_dict() for event in result.outcome_evidence],
        "issues": [issue.to_dict() for issue in result.issues],
        "outcome": result.outcome.value,
        "outcome_subreason": result.outcome_subreason,
    }
