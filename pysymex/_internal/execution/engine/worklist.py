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

"""Outer worklist-draining lifecycle for symbolic execution runs."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.execution.resources.events import record_resource_limit_degradation
from pysymex._internal.execution.scheduling.rewards import calculate_path_reward
from pysymex._internal.execution.strategies.manager.path import AdaptivePathManager
from pysymex._internal.limits.models import LimitExceeded
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.limits.tracker import ResourceTracker
    from pysymex._internal.typing.protocols import SolverProtocol

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class WorklistLoopContext:
    """Concrete owners and callbacks needed to drain one execution worklist."""

    session: ExecutionSession
    config: ExecutionConfig
    solver: SolverProtocol
    resource_tracker: ResourceTracker | None
    execute_step: Callable[[VMState], None]


def drain_worklist(context: WorklistLoopContext) -> None:
    """Drain the session worklist until it is empty or a resource limit stops it."""
    worklist = context.session.worklist
    if worklist is None:
        return
    if context.resource_tracker is not None:
        context.resource_tracker.start()

    timeout_seconds = context.config.timeout_seconds
    context.solver.set_deadline(
        time.perf_counter() + timeout_seconds if timeout_seconds is not None else None,
    )

    active_solver_token = SolverContext.active.set(context.solver)
    try:
        while not worklist.is_empty():
            context.session.iterations += 1
            try:
                if context.resource_tracker is not None:
                    context.resource_tracker.check_all_limits()
                    context.resource_tracker.record_iteration()
            except LimitExceeded as exc:
                record_resource_limit_degradation(
                    exc=exc,
                    session=context.session,
                    reason="exploration stopped by resource limit",
                )
                break
            state = worklist.get_next_state()
            if state is None:
                break
            if logger.state.trace_enabled:
                logger.trace(
                    "scheduled path_id=%d pc=%d depth=%d pending=%d",
                    state.path_id,
                    state.pc,
                    state.depth,
                    state.pending_constraint_count,
                )

            coverage_before = len(context.session.coverage)
            issues_before = len(context.session.issues)

            step_start = time.perf_counter()
            context.execute_step(state)
            context.session.phase_timers_seconds["execute_step"] += time.perf_counter() - step_start
            context.session.phase_counts["execute_step"] += 1

            if isinstance(worklist, AdaptivePathManager):
                new_coverage = len(context.session.coverage) - coverage_before
                new_issues = len(context.session.issues) - issues_before
                reward = calculate_path_reward(
                    new_coverage=new_coverage,
                    new_issues=new_issues,
                )
                worklist.record_reward(reward)

            try:
                if context.resource_tracker is not None:
                    context.resource_tracker.check_time_limit()
            except LimitExceeded as exc:
                record_resource_limit_degradation(
                    exc=exc,
                    session=context.session,
                    state=state,
                    reason="exploration stopped by time limit",
                )
                break
    finally:
        context.solver.set_deadline(None)
        SolverContext.active.reset(active_solver_token)
