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

"""Direct call dispatch and resume preparation for modeled coroutines."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.types import CallFrame
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.coroutines.aliases import replace_coroutine_aliases
from pysymex._internal.execution.opcodes.common.coroutines.objects import (
    COROUTINE_RESUME_PROTOCOL,
    CoroutineResumeRequest,
    ModeledCoroutine,
)
from pysymex._internal.execution.opcodes.common.coroutines.results import (
    exception_from_throw_args,
    runtime_error_result,
    type_error_result,
    unsupported_coroutine,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def create_coroutine_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Return a lazy coroutine object without executing its function body."""
    name = str(getattr(func_obj, "__name__", None) or getattr(func_obj, "_func_name", "coroutine"))
    coroutine = ModeledCoroutine(name, func_obj, tuple(args), tuple(kwargs.items()))
    return OpcodeResult.continue_with(state.push(cast("StackValue", coroutine)).advance_pc())


def try_dispatch_coroutine_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None = None,
    instr: dis.Instruction | None = None,
) -> OpcodeResult | None:
    """Dispatch supported direct calls on modeled coroutine objects."""
    if kwargs:
        return None
    receiver = getattr(func_obj, "__self__", None)
    method_name = getattr(func_obj, "__name__", None)
    if not isinstance(receiver, ModeledCoroutine):
        return None

    if method_name == "close" and not args:
        closed = dataclasses.replace(receiver, closed=True)
        replace_coroutine_aliases(state, receiver, closed)
        return OpcodeResult.continue_with(state.push(SymbolicNoneType()).advance_pc())

    if method_name == "throw" and args:
        if ctx is None or instr is None:
            return unsupported_coroutine(
                state,
                "coroutine throw dispatch was requested without caller bytecode context",
            )
        return _throw_coroutine_call(state, ctx, instr, receiver, args)

    if method_name != "send" or len(args) != 1:
        return None
    if ctx is None or instr is None:
        return unsupported_coroutine(
            state,
            "coroutine send dispatch was requested without caller bytecode context",
        )
    return _send_coroutine_call(state, ctx, instr, receiver, args[0])


def _send_coroutine_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    coroutine: ModeledCoroutine,
    sent: StackValue,
) -> OpcodeResult:
    """Resume a modeled coroutine for a direct ``coroutine.send(value)`` call."""
    if coroutine.closed:
        return runtime_error_result(state, ctx, instr, "cannot reuse already awaited coroutine")
    if coroutine.started:
        if not _is_none(sent):
            return type_error_result(
                state,
                ctx,
                instr,
                "can't send non-None value to a running coroutine",
            )
        return _resume_suspended_coroutine(state, ctx, instr, coroutine, sent)
    if not _is_none(sent):
        return type_error_result(
            state,
            ctx,
            instr,
            "can't send non-None value to a just-started coroutine",
        )

    return _start_coroutine(state, ctx, coroutine, CoroutineResumeRequest(coroutine))


def _start_coroutine(
    state: VMState,
    ctx: OpcodeDispatcher,
    coroutine: ModeledCoroutine,
    request: CoroutineResumeRequest,
) -> OpcodeResult:
    """Enter a cold modeled coroutine via interprocedural execution."""
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        coroutine.function,
        list(coroutine.args),
        dict(coroutine.kwargs),
        protocol_method=COROUTINE_RESUME_PROTOCOL,
        protocol_retained_operand=cast("StackValue", request),
    )
    if result is None or result.terminal or len(result.new_states) != 1:
        return unsupported_coroutine(
            state,
            "coroutine body could not be entered precisely",
        )
    first_body_pc = _first_body_pc(ctx.instructions)
    if first_body_pc is None:
        return unsupported_coroutine(
            state,
            "coroutine bytecode body entry point could not be located",
        )
    return OpcodeResult.continue_with(result.new_states[0].set_pc(first_body_pc))


def _resume_suspended_coroutine(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    coroutine: ModeledCoroutine,
    sent: StackValue | None,
) -> OpcodeResult:
    """Re-enter a suspended coroutine frame with *sent* on its stack."""
    prepared = _prepare_suspended_coroutine_state(
        state,
        ctx,
        instr,
        coroutine,
        CoroutineResumeRequest(coroutine),
    )
    if prepared is None:
        return unsupported_coroutine(
            state,
            "suspended coroutine state is incomplete",
        )
    resumed_state = prepared
    resumed_state.stack = [*coroutine.suspended_stack, sent]
    resumed_state = resumed_state.set_pc(cast("int", coroutine.resume_pc))
    return OpcodeResult.continue_with(resumed_state)


def _throw_coroutine_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    coroutine: ModeledCoroutine,
    args: list[StackValue],
) -> OpcodeResult:
    """Inject an exception into a suspended modeled coroutine."""
    if coroutine.closed:
        return runtime_error_result(state, ctx, instr, "cannot reuse already awaited coroutine")
    if not coroutine.started:
        return type_error_result(
            state,
            ctx,
            instr,
            "can't throw into a just-started coroutine",
        )
    exc = exception_from_throw_args(args)
    if exc is None:
        return unsupported_coroutine(
            state,
            "coroutine throw arguments are not modeled precisely",
        )
    prepared = _prepare_suspended_coroutine_state(
        state,
        ctx,
        instr,
        coroutine,
        CoroutineResumeRequest(coroutine),
    )
    if prepared is None or coroutine.resume_pc is None:
        return unsupported_coroutine(
            state,
            "suspended coroutine state is incomplete",
        )

    instructions = cast("list[dis.Instruction]", prepared.current_instructions)
    if not 0 <= coroutine.resume_pc < len(instructions):
        return unsupported_coroutine(
            state,
            "suspended coroutine resume point is outside the retained bytecode",
        )
    resume_offset = instructions[coroutine.resume_pc].offset
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    handled = ExceptionFlow.jump_to_handler(prepared, ctx, int(resume_offset), exc)
    if handled is None:
        issue = Issue(
            kind=IssueKind.UNHANDLED_EXCEPTION,
            message=f"Possible unhandled exception: {exc.type_name}",
            constraints=list(prepared.path_constraints),
            pc=prepared.pc,
        )
        return OpcodeResult.error(issue)
    return OpcodeResult.continue_with(handled)


def _prepare_suspended_coroutine_state(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    coroutine: ModeledCoroutine,
    request: CoroutineResumeRequest,
) -> VMState | None:
    """Build a callee frame from a stored suspended coroutine continuation."""
    if (
        coroutine.suspended_locals is None
        or coroutine.resume_pc is None
        or not coroutine.instructions
    ):
        return None
    frame = CallFrame(
        function_name=coroutine.name,
        return_pc=state.pc + 1,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_stack=tuple(state.stack),
        caller_instructions=cast("list[object]", list(ctx.instructions)),
        protocol_method=COROUTINE_RESUME_PROTOCOL,
        protocol_retained_operand=cast("StackValue", request),
        caller_offset=instr.offset,
    )
    instructions = list(coroutine.instructions)
    state = state.push_call(frame)
    state.local_vars = coroutine.suspended_locals.cow_fork()
    state.stack = list(coroutine.suspended_stack)
    state.current_instructions = cast("list[object]", instructions)
    ctx.register_exception_entries(instructions, list(coroutine.exception_entries))
    ctx.set_instructions(instructions)
    state.depth += 1
    state.invalidate_cached_hash()
    return state


def _first_body_pc(instructions: list[dis.Instruction]) -> int | None:
    """Return the PC after ``RETURN_GENERATOR`` and the following ``RESUME``."""
    saw_return_generator = False
    for index, instruction in enumerate(instructions):
        if instruction.opname == "RETURN_GENERATOR":
            saw_return_generator = True
        elif saw_return_generator and instruction.opname == "RESUME":
            return index + 1
    return None


def _is_none(value: object) -> bool:
    """Return whether *value* represents the ``None`` sent into a cold coroutine."""
    return value is None or isinstance(value, SymbolicNoneType)
