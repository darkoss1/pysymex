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

"""Opcode-result issue publication helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Protocol

from pysymex.logger import get_logger

from pysymex.core.state.record import VMState
from pysymex.execution.detectors.publication import publish_deferred_issue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.resources import record_resource_limit_prune
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.step import record_terminal_path
from pysymex.resources.models import LimitExceeded

__all__ = [
    "publish_opcode_result_fallback_events",
    "publish_opcode_result_issues",
    "route_successor_opcode_result",
    "route_terminal_opcode_result",
]

logger = get_logger(__name__)

HookMap = Mapping[str, Sequence[Callable[..., object]]]
LineNumberResolver = Callable[[int], int | None]
PathCompleteCallback = Callable[[VMState], None]
RecordDegradedPasses = Callable[[list[str]], None]
RecordPathExplored = Callable[[], None]


class PathResourceTracker(Protocol):
    """Resource tracker protocol needed for additional successor paths."""

    def record_path(self) -> int: ...


def publish_opcode_result_issues(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    resolve_line_number: LineNumberResolver,
) -> None:
    """Publish opcode-result issues to the session and issue hooks."""
    for issue in result.issues:
        line_no = resolve_line_number(issue.pc)
        if line_no != issue.line_number:
            issue = replace(issue, line_number=line_no)
        session.issues.append(issue)
        for hook in hooks.get("on_issue", ()):
            try:
                hook(hook_owner, state, issue)
            except Exception:
                logger.exception("Plugin hook execution failed")


def publish_opcode_result_fallback_events(
    *,
    session: ExecutionSession,
    result: OpcodeResult,
) -> None:
    """Record structured opcode fallback events into the execution session."""
    for event in result.fallback_events:
        session.record_fallback_event(event)


def route_terminal_opcode_result(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    on_path_complete: PathCompleteCallback,
) -> bool:
    """Route terminal opcode results and return whether routing consumed the result."""
    if not result.terminal:
        return False

    if not result.degraded_passes:
        for deferred in state.deferred_detector_issues:
            publish_deferred_issue(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
                deferred=deferred,
            )
    state.deferred_detector_issues = []
    state.invalidate_cached_hash()
    if logger.state.trace_enabled:
        logger.trace(
            "terminal path path_id=%d pc=%d issues=%d",
            state.path_id,
            state.pc,
            len(result.issues),
        )
    record_terminal_path(
        session=session,
        state=state,
        include_stack=True,
        final_exception=result.issues[0] if result.issues else None,
        update_exception=True,
    )
    on_path_complete(state)
    return True


def route_successor_opcode_result(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
    resource_tracker: PathResourceTracker | None,
    record_degraded_passes: RecordDegradedPasses,
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
                        record_degraded_passes=record_degraded_passes,
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
