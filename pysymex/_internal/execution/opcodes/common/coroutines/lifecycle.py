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

"""Suspension and return lifecycle operations for modeled coroutines."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.coroutines.aliases import replace_coroutine_aliases
from pysymex._internal.execution.opcodes.common.coroutines.objects import (
    COROUTINE_RESUME_PROTOCOL,
    CoroutineResumeRequest,
)
from pysymex._internal.execution.opcodes.common.coroutines.results import raise_stop_iteration

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def complete_coroutine_return(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    return_value: object | None = None,
) -> OpcodeResult | None:
    """Complete a resumed coroutine return as ``StopIteration.value`` semantics."""
    request = frame.protocol_retained_operand
    if frame.protocol_method != COROUTINE_RESUME_PROTOCOL or not isinstance(
        request,
        CoroutineResumeRequest,
    ):
        return None
    closed = dataclasses.replace(request.coroutine, started=True, closed=True)
    _restore_caller(state, ctx, frame)
    replace_coroutine_aliases(state, request.coroutine, closed)
    state.depth = max(0, state.depth - 1)
    return raise_stop_iteration(state, ctx, frame, return_value)


def suspend_coroutine_yield_or_none(
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Suspend an executing modeled coroutine at a yielded await point."""
    frame = state.call_stack[-1] if state.call_stack else None
    request = frame.protocol_retained_operand if frame is not None else None
    if (
        frame is None
        or frame.protocol_method != COROUTINE_RESUME_PROTOCOL
        or not isinstance(request, CoroutineResumeRequest)
    ):
        return None

    yielded = state.pop()
    updated = dataclasses.replace(
        request.coroutine,
        started=True,
        suspended_locals=state.local_vars.cow_fork(),
        suspended_stack=tuple(state.stack),
        instructions=tuple(ctx.instructions),
        exception_entries=tuple(getattr(ctx, "_exception_entries", ())),
        resume_pc=state.pc + 1,
    )
    state.pop_call()
    _restore_caller(state, ctx, frame)
    replace_coroutine_aliases(state, request.coroutine, updated)
    state = state.set_pc(frame.return_pc).push(yielded)
    state.depth = max(0, state.depth - 1)
    return OpcodeResult.continue_with(state)


def coroutine_resume_active(state: VMState) -> bool:
    """Return whether the active frame is executing a modeled coroutine resume."""
    frame = state.call_stack[-1] if state.call_stack else None
    return frame is not None and frame.protocol_method == COROUTINE_RESUME_PROTOCOL


def _restore_caller(state: VMState, ctx: OpcodeDispatcher, frame: CallFrame) -> None:
    """Restore caller stack, locals, and bytecode after coroutine completion."""
    from pysymex._internal.execution.opcodes.common.control.returns.state import (
        apply_argument_alias_updates,
        restore_caller_stack,
    )

    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    if frame.caller_instructions is not None:
        instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", instructions)
        ctx.set_instructions(instructions)
