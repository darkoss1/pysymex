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

"""Detector issue deferral, suppression, and publication helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import cast
import dis

from pysymex.logger import get_logger

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.core.state.record import VMState
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.session.state import ExecutionSession

logger = get_logger(__name__)

HookMap = Mapping[str, Sequence[Callable[..., object]]]
DetectorSiteKey = tuple[int, int, IssueKind]


def _detector_issue_payload(deferred: DeferredStateIssue) -> Issue:
    """Return a detector issue payload from a core-neutral deferred token."""
    issue = deferred.issue
    if not isinstance(issue, Issue):
        raise TypeError("deferred detector token payload must be an Issue")
    return issue


def _detector_site_key(deferred: DeferredStateIssue) -> DetectorSiteKey:
    """Return the detector publication key from a core-neutral deferred token."""
    site_key: object = deferred.site_key
    if not isinstance(site_key, tuple):
        raise TypeError("deferred detector token site_key must be (int, int, IssueKind)")
    parts = cast("tuple[object, ...]", site_key)
    if len(parts) != 3:
        raise TypeError("deferred detector token site_key must be (int, int, IssueKind)")
    instruction_list_id, pc, kind = parts
    if not isinstance(instruction_list_id, int) or not isinstance(pc, int):
        raise TypeError("deferred detector token site_key must be (int, int, IssueKind)")
    if not isinstance(kind, IssueKind):
        raise TypeError("deferred detector token site_key must be (int, int, IssueKind)")
    return (instruction_list_id, pc, kind)


def _with_except_handler_for_offset(
    dispatcher: OpcodeDispatcher,
    offset: int,
) -> bool:
    handler_index = dispatcher.find_exception_handler(offset)
    if handler_index is None or handler_index + 1 >= len(dispatcher.instructions):
        return False
    first = dispatcher.instructions[handler_index]
    second = dispatcher.instructions[handler_index + 1]
    return first.opname == "PUSH_EXC_INFO" and second.opname == "WITH_EXCEPT_START"


def should_defer_dynamic_with_issue(
    dispatcher: OpcodeDispatcher, state: VMState, instr: dis.Instruction
) -> bool:
    """Return whether a modeled ``__exit__`` must decide issue publication."""
    if not _with_except_handler_for_offset(dispatcher, instr.offset):
        return False
    if instr.opname == "RAISE_VARARGS":
        return True
    from pysymex.models.objects import SymbolicMethod

    return any(
        isinstance(value, SymbolicMethod) and value.name == "__exit__" for value in state.stack
    )


def should_replace_dynamic_exit_issue(state: VMState) -> bool:
    """Return whether a ``with`` cleanup exception replaces a deferred body issue."""
    if not state.deferred_detector_issues or not state.call_stack:
        return False
    frame = state.call_stack[-1]
    if frame.protocol_method == "__exit__":
        return True
    return frame.protocol_method in {"__bool__", "__len__"} and _truth_call_from_with_exit(frame)


def _truth_call_from_with_exit(frame: object) -> bool:
    """Return whether a truth protocol call is testing a ``WITH_EXCEPT_START`` result."""
    raw_instructions = getattr(frame, "caller_instructions", None)
    raw_offset = getattr(frame, "caller_offset", None)
    if not isinstance(raw_instructions, list) or not isinstance(raw_offset, int):
        return False

    caller_instructions = cast("list[object]", raw_instructions)
    for index, instruction in enumerate(caller_instructions):
        if not isinstance(instruction, dis.Instruction) or instruction.offset != raw_offset:
            continue
        if instruction.opname == "TO_BOOL":
            return _previous_instruction_is_with_except_start(caller_instructions, index)
        if instruction.opname in {"POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_IF_TRUE"}:
            return _previous_instruction_is_with_except_start(caller_instructions, index)
        return False
    return False


def _previous_instruction_is_with_except_start(
    instructions: Sequence[object],
    index: int,
) -> bool:
    if index <= 0:
        return False
    previous = instructions[index - 1]
    return isinstance(previous, dis.Instruction) and previous.opname == "WITH_EXCEPT_START"


def route_deferred_detector_issues(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    result: OpcodeResult,
    state: VMState,
) -> None:
    """Forward session-level deferred issues to a successor state or publish them.

    Drains ``session.deferred_detector_issues`` and checks each successor state
    in ``result.new_states`` for the ``PUSH_EXC_INFO / WITH_EXCEPT_START`` pair
    that indicates a ``with``-block exception-handler path. Issues are attached
    to the first matching successor state so the context manager's ``__exit__``
    can decide whether to suppress them.
    """
    deferred = session.deferred_detector_issues
    session.deferred_detector_issues = []
    if not deferred:
        return
    routed = False
    for next_state in result.new_states:
        instructions = next_state.current_instructions
        if instructions is None or next_state.pc + 1 >= len(instructions):
            continue
        first = instructions[next_state.pc]
        second = instructions[next_state.pc + 1]
        if (
            getattr(first, "opname", "") == "PUSH_EXC_INFO"
            and getattr(second, "opname", "") == "WITH_EXCEPT_START"
        ):
            next_state.deferred_detector_issues.extend(deferred)
            next_state.invalidate_cached_hash()
            routed = True
    if not routed:
        for pending in deferred:
            publish_deferred_issue(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
                deferred=pending,
            )


def publish_deferred_issue(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
    deferred: DeferredStateIssue,
) -> None:
    """Publish a deferred detector issue if its site has not already been reported."""
    site_key = _detector_site_key(deferred)
    if site_key in session.reported_detector_sites:
        return
    issue = _detector_issue_payload(deferred)
    session.reported_detector_sites.add(site_key)
    session.issues.append(issue)
    for hook in hooks.get("on_issue", ()):
        try:
            hook(hook_owner, state, issue)
        except Exception:
            logger.exception("Plugin hook execution failed")


def record_suppressed_dynamic_with_issues(
    *,
    session: ExecutionSession,
    result: OpcodeResult,
) -> None:
    """Record bytecode offsets for detector issues suppressed by successful ``__exit__``."""
    for next_state in result.new_states:
        if not next_state.deferred_detector_issues:
            continue
        instructions = next_state.current_instructions
        if instructions is None or next_state.pc < 0 or next_state.pc >= len(instructions):
            continue
        if getattr(instructions[next_state.pc], "opname", "") == "RERAISE":
            continue
        for deferred in next_state.deferred_detector_issues:
            issue_pc = _detector_site_key(deferred)[1]
            if not 0 <= issue_pc < len(instructions):
                continue
            issue_instruction = instructions[issue_pc]
            if isinstance(issue_instruction, dis.Instruction):
                session.suppressed_detector_offsets.add(issue_instruction.offset)
