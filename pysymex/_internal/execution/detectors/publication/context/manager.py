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

"""Dynamic context-manager detector deferral policy."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def should_defer_dynamic_with_issue(
    dispatcher: OpcodeDispatcher,
    state: VMState,
    instr: dis.Instruction,
) -> bool:
    """Return whether a modeled ``__exit__`` must decide issue publication."""
    if not with_except_handler_for_offset(dispatcher, instr.offset):
        return False
    if instr.opname == "RAISE_VARARGS":
        return True
    from pysymex._internal.core.classes.types import SymbolicMethod

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
    return frame.protocol_method in {"__bool__", "__len__"} and truth_call_from_with_exit(frame)


def with_except_handler_for_offset(
    dispatcher: OpcodeDispatcher,
    offset: int,
) -> bool:
    """Return whether ``offset`` routes into a ``WITH_EXCEPT_START`` handler."""
    handler_index = dispatcher.find_exception_handler(offset)
    if handler_index is None or handler_index + 1 >= len(dispatcher.instructions):
        return False
    first = dispatcher.instructions[handler_index]
    second = dispatcher.instructions[handler_index + 1]
    return first.opname == "PUSH_EXC_INFO" and second.opname == "WITH_EXCEPT_START"


def truth_call_from_with_exit(frame: object) -> bool:
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
            return prev_is_with_except_start(caller_instructions, index)
        if instruction.opname in {"POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_IF_TRUE"}:
            return prev_is_with_except_start(caller_instructions, index)
        return False
    return False


def prev_is_with_except_start(
    instructions: Sequence[object],
    index: int,
) -> bool:
    """Return whether the previous instruction is ``WITH_EXCEPT_START``."""
    if index <= 0:
        return False
    previous = instructions[index - 1]
    return isinstance(previous, dis.Instruction) and previous.opname == "WITH_EXCEPT_START"
