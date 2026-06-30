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

"""Execution result finalization after worklist exploration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.finalization import filter_final_issues
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.scheduling.stats import (
    collect_state_merger_stats,
    collect_worklist_stats,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.strategies.merger.state import StateMerger
    from pysymex._internal.limits.tracker import ResourceTracker
    from pysymex._internal.typing.protocols import SolverProtocol


def finalize_execution_result(
    *,
    session: ExecutionSession,
    enable_fp_filtering: bool,
    resource_tracker: ResourceTracker | None,
    solver: SolverProtocol,
    detector_query_stats: dict[str, object],
    state_merger: StateMerger | None,
    function_name: str,
    source_file: str,
    include_final_stack: bool,
    include_final_exception: bool,
) -> ExecutionResult:
    """Coordinate final result construction after a completed execution run."""
    if resource_tracker is None:
        msg = "Resource tracker is unavailable"
        raise RuntimeError(msg)
    return ExecutionResult.from_session(
        session=session,
        final_issues=filter_final_issues(
            session=session,
            enable_fp_filtering=enable_fp_filtering,
        ),
        resource_snapshot=resource_tracker.snapshot(),
        solver_stats=solver.get_stats(),
        detector_query_stats=detector_query_stats,
        state_merger_stats=collect_state_merger_stats(state_merger),
        worklist_stats=collect_worklist_stats(session.worklist),
        function_name=function_name,
        source_file=source_file,
        include_final_stack=include_final_stack,
        include_final_exception=include_final_exception,
    )
