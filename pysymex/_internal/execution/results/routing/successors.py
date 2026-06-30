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

"""Nonterminal opcode-result successor routing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.resources.events import record_resource_limit_prune
from pysymex._internal.limits.models import LimitExceeded
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.execution.results.routing.types import (
        HookMap,
        PathResourceTracker,
        RecordPathExplored,
    )
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


def route_successor_opcode_result(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    resource_tracker: PathResourceTracker | None,
    record_path_explored: RecordPathExplored,
) -> None:
    """Queue nonterminal successor states and fire fork hooks."""
    states_to_process = result.new_states
    if states_to_process:
        first_state = states_to_process[0]
        first_state.depth = state.depth + 1
        if session.worklist:
            session.worklist.add_state(first_state)
            if logger.state.trace_enabled:
                logger.trace(
                    "queued path path_id=%d pc=%d depth=%d primary=true",
                    first_state.path_id,
                    first_state.pc,
                    first_state.depth,
                )

        for new_state in states_to_process[1:]:
            can_add = True
            if resource_tracker is not None:
                try:
                    resource_tracker.record_path()
                except LimitExceeded as exc:
                    record_resource_limit_prune(
                        session=session,
                        exc=exc,
                        state=new_state,
                    )
                    can_add = False

            if can_add:
                new_state.depth = state.depth + 1
                if session.worklist:
                    session.worklist.add_state(new_state)
                    if logger.state.trace_enabled:
                        logger.trace(
                            "queued path path_id=%d pc=%d depth=%d primary=false",
                            new_state.path_id,
                            new_state.pc,
                            new_state.depth,
                        )
                session.paths_explored += 1
                record_path_explored()

    fork_hooks = hooks.get("on_fork")
    if len(states_to_process) >= 2 and (logger.state.trace_enabled or fork_hooks):
        if logger.state.trace_enabled:
            logger.trace(
                "fork emitted parent_path_id=%d pc=%d fork_count=%d",
                state.path_id,
                state.pc,
                len(states_to_process),
            )
        if fork_hooks:
            for hook in fork_hooks:
                try:
                    hook(hook_owner, state, list(states_to_process))
                except Exception:
                    logger.exception("Plugin hook execution failed")
