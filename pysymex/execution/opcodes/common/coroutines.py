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

"""Lazy coroutine objects returned by async-function calls."""

from __future__ import annotations

import dataclasses
import dis
import itertools
from dataclasses import dataclass
from dataclasses import field
from typing import TYPE_CHECKING, cast

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.types import CallFrame
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.havoc import HavocValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control_fallbacks import (
    UNSUPPORTED_GENERATOR,
    unsupported_generator_event,
)

if TYPE_CHECKING:
    from pysymex.core.memory.cow.collections import CowDict
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue

COROUTINE_RESUME_PROTOCOL = "__coroutine_resume__"
_COROUTINE_ID_COUNTER = itertools.count()


def _next_coroutine_identity() -> int:
    """Return a process-local coroutine identity stable across dataclass copies."""
    return next(_COROUTINE_ID_COUNTER)


@dataclass(frozen=True, slots=True)
class ModeledCoroutine:
    """Path-local coroutine object created by calling an ``async def`` function."""

    name: str
    function: object
    args: tuple[StackValue, ...]
    kwargs: tuple[tuple[str, StackValue], ...]
    started: bool = False
    closed: bool = False
    suspended_locals: CowDict[str, StackValue] | None = None
    suspended_stack: tuple[StackValue, ...] = ()
    instructions: tuple[dis.Instruction, ...] = ()
    exception_entries: tuple[object, ...] = ()
    resume_pc: int | None = None
    identity: int = field(default_factory=_next_coroutine_identity)

    def send(self, _value: object) -> object:
        """Send must be dispatched by symbolic execution, not called natively."""
        raise RuntimeError("ModeledCoroutine.send must be dispatched by the symbolic VM")

    def throw(self, *_args: object) -> object:
        """Throw must be dispatched by symbolic execution, not called natively."""
        raise RuntimeError("ModeledCoroutine.throw must be dispatched by the symbolic VM")

    def close(self) -> object:
        """Close must be dispatched by symbolic execution, not called natively."""
        raise RuntimeError("ModeledCoroutine.close must be dispatched by the symbolic VM")

    def __await__(self) -> object:
        """Await must be dispatched by symbolic execution, not called natively."""
        raise RuntimeError("ModeledCoroutine.__await__ must be dispatched by the symbolic VM")


@dataclass(frozen=True, slots=True)
class _CoroutineResumeRequest:
    coroutine: ModeledCoroutine


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
        _replace_coroutine_aliases(state, receiver, closed)
        return OpcodeResult.continue_with(state.push(SymbolicNone()).advance_pc())

    if method_name == "throw" and args:
        if ctx is None or instr is None:
            return _unsupported_coroutine_result(
                state,
                "coroutine throw dispatch was requested without caller bytecode context",
            )
        return _throw_coroutine_call(state, ctx, instr, receiver, args)

    if method_name != "send" or len(args) != 1:
        return None
    if ctx is None or instr is None:
        return _unsupported_coroutine_result(
            state,
            "coroutine send dispatch was requested without caller bytecode context",
        )
    return _send_coroutine_call(state, ctx, instr, receiver, args[0])


def complete_coroutine_return(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    return_value: object | None = None,
) -> OpcodeResult | None:
    """Complete a resumed coroutine return as ``StopIteration.value`` semantics."""
    request = frame.protocol_retained_operand
    if frame.protocol_method != COROUTINE_RESUME_PROTOCOL or not isinstance(
        request, _CoroutineResumeRequest
    ):
        return None
    closed = dataclasses.replace(request.coroutine, started=True, closed=True)
    _restore_caller(state, ctx, frame)
    _replace_coroutine_aliases(state, request.coroutine, closed)
    state.depth = max(0, state.depth - 1)
    return _raise_stop_iteration(state, ctx, frame, return_value)


def _send_coroutine_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    coroutine: ModeledCoroutine,
    sent: StackValue,
) -> OpcodeResult:
    """Resume a modeled coroutine for a direct ``coroutine.send(value)`` call."""
    if coroutine.closed:
        return _runtime_error_result(state, ctx, instr, "cannot reuse already awaited coroutine")
    if coroutine.started:
        if not _is_none(sent):
            return _type_error_result(
                state,
                ctx,
                instr,
                "can't send non-None value to a running coroutine",
            )
        return _resume_suspended_coroutine(state, ctx, instr, coroutine, sent)
    if not _is_none(sent):
        return _type_error_result(
            state,
            ctx,
            instr,
            "can't send non-None value to a just-started coroutine",
        )

    return _start_coroutine(state, ctx, coroutine, _CoroutineResumeRequest(coroutine))


def _start_coroutine(
    state: VMState,
    ctx: OpcodeDispatcher,
    coroutine: ModeledCoroutine,
    request: _CoroutineResumeRequest,
) -> OpcodeResult:
    """Enter a cold modeled coroutine via interprocedural execution."""
    from pysymex.execution.calls.interprocedural import (
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
        return _unsupported_coroutine_result(
            state,
            "coroutine body could not be entered precisely",
        )
    first_body_pc = _first_body_pc(ctx.instructions)
    if first_body_pc is None:
        return _unsupported_coroutine_result(
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
        _CoroutineResumeRequest(coroutine),
    )
    if prepared is None:
        return _unsupported_coroutine_result(
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
        return _runtime_error_result(state, ctx, instr, "cannot reuse already awaited coroutine")
    if not coroutine.started:
        return _type_error_result(
            state,
            ctx,
            instr,
            "can't throw into a just-started coroutine",
        )
    exc = _exception_from_throw_args(args)
    if exc is None:
        return _unsupported_coroutine_result(
            state,
            "coroutine throw arguments are not modeled precisely",
        )
    prepared = _prepare_suspended_coroutine_state(
        state,
        ctx,
        instr,
        coroutine,
        _CoroutineResumeRequest(coroutine),
    )
    if prepared is None or coroutine.resume_pc is None:
        return _unsupported_coroutine_result(
            state,
            "suspended coroutine state is incomplete",
        )

    instructions = cast("list[dis.Instruction]", prepared.current_instructions)
    if not 0 <= coroutine.resume_pc < len(instructions):
        return _unsupported_coroutine_result(
            state,
            "suspended coroutine resume point is outside the retained bytecode",
        )
    resume_offset = instructions[coroutine.resume_pc].offset
    from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler

    handled = jump_to_exception_handler(prepared, ctx, int(resume_offset), exc)
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
    request: _CoroutineResumeRequest,
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
        or not isinstance(request, _CoroutineResumeRequest)
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
    _replace_coroutine_aliases(state, request.coroutine, updated)
    state = state.set_pc(frame.return_pc).push(yielded)
    state.depth = max(0, state.depth - 1)
    return OpcodeResult.continue_with(state)


def coroutine_resume_active(state: VMState) -> bool:
    """Return whether the active frame is executing a modeled coroutine resume."""
    frame = state.call_stack[-1] if state.call_stack else None
    return frame is not None and frame.protocol_method == COROUTINE_RESUME_PROTOCOL


def _first_body_pc(instructions: list[dis.Instruction]) -> int | None:
    """Return the PC after ``RETURN_GENERATOR`` and the following ``RESUME``."""
    saw_return_generator = False
    for index, instruction in enumerate(instructions):
        if instruction.opname == "RETURN_GENERATOR":
            saw_return_generator = True
        elif saw_return_generator and instruction.opname == "RESUME":
            return index + 1
    return None


def _restore_caller(state: VMState, ctx: OpcodeDispatcher, frame: CallFrame) -> None:
    """Restore caller stack, locals, and bytecode after coroutine completion."""
    from pysymex.execution.opcodes.common.control.return_state import (
        apply_argument_alias_updates,
        restore_caller_stack,
    )

    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    if frame.caller_instructions is not None:
        instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", instructions)
        ctx.set_instructions(instructions)


def _raise_stop_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
    return_value: object | None = None,
) -> OpcodeResult:
    """Route or report ``StopIteration`` for ``coroutine.send(None)`` completion."""
    from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler

    if return_value is None or isinstance(return_value, SymbolicNone):
        exc = SymbolicException.concrete(StopIteration, raised_at=state.pc)
    else:
        exc = SymbolicException.concrete(StopIteration, return_value, raised_at=state.pc)
    if frame.caller_offset is not None:
        handled = jump_to_exception_handler(state, ctx, frame.caller_offset, exc)
        if handled is not None:
            return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Possible unhandled exception: StopIteration",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _type_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    message: str,
) -> OpcodeResult:
    """Jump to a ``TypeError`` handler or emit a definite type-error issue."""
    from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler

    exc = SymbolicException.concrete(TypeError, message, raised_at=state.pc)
    handled = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handled is not None:
        return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _runtime_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    message: str,
) -> OpcodeResult:
    """Jump to a ``RuntimeError`` handler or emit an unhandled exception issue."""
    from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler

    exc = SymbolicException.concrete(RuntimeError, message, raised_at=state.pc)
    handled = jump_to_exception_handler(state, ctx, instr.offset, exc)
    if handled is not None:
        return OpcodeResult.continue_with(handled)
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Possible unhandled exception: RuntimeError",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _unsupported_coroutine_result(state: VMState, reason: str) -> OpcodeResult:
    """Havoc a coroutine protocol result when precise resume is unsupported."""
    fallback_event = unsupported_generator_event(state=state, reason=reason)
    value, constraint = HavocValue.havoc(f"havoc_coroutine_send_{state.pc}")
    state = state.push(value).add_constraint(constraint).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def _exception_from_throw_args(args: list[StackValue]) -> SymbolicException | None:
    """Return the exception injected by supported ``coroutine.throw`` forms."""
    if not args:
        return None
    first = args[0]
    if isinstance(first, SymbolicException):
        return first
    if isinstance(first, type) and issubclass(first, BaseException):
        return SymbolicException.concrete(first)
    if isinstance(first, BaseException):
        return SymbolicException.concrete(type(first), *first.args)
    return None


def _is_none(value: object) -> bool:
    """Return whether *value* represents the ``None`` sent into a cold coroutine."""
    return value is None or isinstance(value, SymbolicNone)


def _replace_coroutine_aliases(
    state: VMState,
    old: ModeledCoroutine,
    new: ModeledCoroutine,
) -> None:
    """Replace *old* coroutine references in locals, globals, and the stack."""
    for name, value in tuple(state.local_vars.items()):
        state = state.set_local(str(name), cast("StackValue", _replace_value(value, old, new)))
    for name, value in tuple(state.global_vars.items()):
        state = state.set_global(str(name), cast("StackValue", _replace_value(value, old, new)))
    state.stack = [cast("StackValue", _replace_value(value, old, new)) for value in state.stack]
    state.invalidate_cached_hash()


def _replace_value(value: object, old: ModeledCoroutine, new: ModeledCoroutine) -> object:
    """Recursively substitute *new* for *old* inside nested container values."""
    if value is old:
        return new
    if isinstance(value, ModeledCoroutine) and value.identity == old.identity:
        return new
    if isinstance(value, list):
        items = cast("list[object]", value)
        return [_replace_value(item, old, new) for item in items]
    if isinstance(value, tuple):
        items = cast("tuple[object, ...]", value)
        return tuple(_replace_value(item, old, new) for item in items)
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        return {key: _replace_value(item, old, new) for key, item in items.items()}
    return value


__all__ = [
    "COROUTINE_RESUME_PROTOCOL",
    "ModeledCoroutine",
    "complete_coroutine_return",
    "coroutine_resume_active",
    "create_coroutine_call",
    "suspend_coroutine_yield_or_none",
    "try_dispatch_coroutine_call",
]
