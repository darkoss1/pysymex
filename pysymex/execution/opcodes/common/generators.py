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

"""Bounded immutable generator continuations that do not share progress across forks."""

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
from pysymex.core.types.havoc import HavocValue
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
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

GENERATOR_RESUME_PROTOCOL = "__generator_resume__"
_GENERATOR_ID_COUNTER = itertools.count()


def _next_generator_identity() -> int:
    """Return a process-local generator identity stable across dataclass copies."""
    return next(_GENERATOR_ID_COUNTER)


@dataclass(frozen=True, slots=True)
class ModeledGenerator:
    """Path-local generator continuation represented by suspended VM state."""

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
    identity: int = field(default_factory=_next_generator_identity)

    def send(self, value: object) -> object:
        """Resume the generator with *value* (must be dispatched by the VM, not natively)."""
        raise RuntimeError("ModeledGenerator.send must be dispatched by the symbolic VM")

    def throw(self, *args: object) -> object:
        """Throw into the generator (must be dispatched by the VM, not natively)."""
        raise RuntimeError("ModeledGenerator.throw must be dispatched by the symbolic VM")

    def close(self) -> object:
        """Close the generator (must be dispatched by the VM, not natively)."""
        raise RuntimeError("ModeledGenerator.close must be dispatched by the symbolic VM")

    def hash_value(self) -> int:
        """Return a stable hash for deduplicating generator continuations in caches."""
        retained = repr(
            (self.function, self.args, self.kwargs, self.suspended_locals, self.suspended_stack)
        )
        return hash((self.name, self.started, self.closed, self.resume_pc, retained))


@dataclass(frozen=True, slots=True)
class _ResumeRequest:
    generator: ModeledGenerator
    operation: str = "resume"
    has_default: bool = False
    default: StackValue | None = None
    for_iter_exit_pc: int | None = None


def _request_for_frame(frame: CallFrame | None) -> _ResumeRequest | None:
    """Return the generator resume request stored on *frame*, if any."""
    value = frame.protocol_retained_operand if frame is not None else None
    return value if isinstance(value, _ResumeRequest) else None


def create_generator_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Return a lazy generator object without executing its function body."""
    name = str(getattr(func_obj, "__name__", None) or getattr(func_obj, "_func_name", "generator"))
    generator = ModeledGenerator(name, func_obj, tuple(args), tuple(kwargs.items()))
    return OpcodeResult.continue_with(state.push(cast("StackValue", generator)).advance_pc())


def literal_generator_yields(generator: ModeledGenerator) -> tuple[object, ...] | None:
    """Return literal yield values for simple finite generators, if fully known."""
    from pysymex.execution.calls.payload import function_payload

    payload = function_payload(generator.function)
    code = payload.code if payload is not None else getattr(generator.function, "__code__", None)
    if code is None:
        return None
    instructions = list(dis.get_instructions(code))
    values: list[object] = []
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE":
            continue
        if index == 0 or instructions[index - 1].opname != "LOAD_CONST":
            return None
        values.append(instructions[index - 1].argval)
    return tuple(values) if values else None


def try_resume_generator_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction | None,
) -> OpcodeResult | None:
    """Resume supported generator ``next``/``send`` operations at a CALL site."""
    if ctx is None or instr is None:
        return None
    request, sent = _resume_request(func_obj, args, kwargs)
    if request is None:
        return None
    generator = request.generator
    if request.operation == "close":
        return _close_generator_call(state, generator)
    if request.operation == "throw":
        return _abstract_generator_call(state)
    if generator.closed:
        return _complete_closed_call(state, ctx, instr, request)
    if not generator.started:
        if sent is not None:
            return _type_error_result(
                state, ctx, instr, "can't send non-None value to a just-started generator"
            )
        return _start_generator(state, ctx, generator, request)
    return _resume_suspended_generator(state, ctx, generator, request, sent)


def resume_generator_for_iter(
    state: VMState,
    ctx: OpcodeDispatcher,
    generator: ModeledGenerator,
    *,
    target_index: int,
    continue_pc: int,
) -> OpcodeResult:
    """Resume a generator for ``FOR_ITER`` while preserving loop-exit semantics."""
    if generator.closed:
        return _complete_closed_for_iter(state, target_index)

    request = _ResumeRequest(generator, for_iter_exit_pc=target_index)
    if not generator.started:
        return _start_generator(state, ctx, generator, request, resume_pc=continue_pc)
    return _resume_suspended_generator(state, ctx, generator, request, None, resume_pc=continue_pc)


def suspend_generator_yield_or_abstract(
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Suspend an executing modeled generator, or retain abstract yield behavior."""
    frame = state.call_stack[-1] if state.call_stack else None
    request = _request_for_frame(frame)
    if frame is None or request is None:
        state.pop()
        from pysymex.core.types.scalars.values import SymbolicValue

        sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state.pc}")
        return OpcodeResult.continue_with(state.push(sent).add_constraint(constraint).advance_pc())

    yielded = state.pop()
    updated = dataclasses.replace(
        request.generator,
        started=True,
        suspended_locals=state.local_vars.cow_fork(),
        suspended_stack=tuple(state.stack),
        instructions=tuple(ctx.instructions),
        exception_entries=tuple(getattr(ctx, "_exception_entries", ())),
        resume_pc=state.pc + 1,
    )
    state.pop_call()
    _restore_caller(state, ctx, frame)
    _replace_generator_aliases(state, request.generator, updated)
    state = state.set_pc(frame.return_pc).push(yielded)
    state.depth = max(0, state.depth - 1)
    return OpcodeResult.continue_with(state)


def complete_generator_return(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    return_value: object | None = None,
) -> OpcodeResult | None:
    """Complete a resumed generator return as ``StopIteration`` semantics."""
    request = _request_for_frame(frame)
    if request is None:
        return None
    closed = dataclasses.replace(request.generator, closed=True)
    _restore_caller(state, ctx, frame)
    _replace_generator_aliases(state, request.generator, closed)
    state.depth = max(0, state.depth - 1)
    if request.for_iter_exit_pc is not None:
        return OpcodeResult.continue_with(
            state.set_pc(request.for_iter_exit_pc).push(SymbolicNone())
        )
    if request.has_default:
        default = request.default if request.default is not None else SymbolicNone()
        return OpcodeResult.continue_with(state.set_pc(frame.return_pc).push(default))
    return _raise_stop_iteration(state, ctx, frame, return_value)


def _resume_request(
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[_ResumeRequest | None, StackValue | None]:
    """Recognize ``next``/``send`` calls on a :class:`ModeledGenerator`."""
    if kwargs:
        return None, None
    func_name = (
        func_obj
        if isinstance(func_obj, str)
        else getattr(func_obj, "__name__", None)
        or getattr(func_obj, "model_name", None)
        or getattr(func_obj, "_name", None)
    )
    if (
        (func_obj is next or func_name in {"next", "builtins.next"})
        and len(args) in {1, 2}
        and isinstance(args[0], ModeledGenerator)
    ):
        return (
            _ResumeRequest(
                args[0],
                has_default=len(args) == 2,
                default=args[1] if len(args) == 2 else None,
            ),
            None,
        )
    owner = getattr(func_obj, "__self__", None)
    method_name = getattr(func_obj, "__name__", None)
    if isinstance(owner, ModeledGenerator) and method_name == "send":
        if len(args) == 1:
            return _ResumeRequest(owner), args[0]
        return None, None
    if isinstance(owner, ModeledGenerator) and method_name == "throw":
        if args:
            return _ResumeRequest(owner, operation="throw"), None
        return None, None
    if isinstance(owner, ModeledGenerator) and method_name == "close":
        if not args:
            return _ResumeRequest(owner, operation="close"), None
        return None, None
    return None, None


def _start_generator(
    state: VMState,
    ctx: OpcodeDispatcher,
    generator: ModeledGenerator,
    request: _ResumeRequest,
    resume_pc: int | None = None,
) -> OpcodeResult:
    """Enter a cold modeled generator via interprocedural call."""
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        generator.function,
        list(generator.args),
        dict(generator.kwargs),
        protocol_method=GENERATOR_RESUME_PROTOCOL,
        resume_pc=resume_pc,
        protocol_retained_operand=cast("StackValue", request),
    )
    if result is None or result.terminal or len(result.new_states) != 1:
        return _abstract_generator_call(state)
    next_state = result.new_states[0]
    first_body_pc = _first_body_pc(ctx.instructions)
    if first_body_pc is None:
        return _abstract_generator_call(state)
    return OpcodeResult.continue_with(next_state.set_pc(first_body_pc))


def _first_body_pc(instructions: list[dis.Instruction]) -> int | None:
    """Return the PC after ``RETURN_GENERATOR`` and the following ``RESUME``."""
    saw_return_generator = False
    for index, instruction in enumerate(instructions):
        if instruction.opname == "RETURN_GENERATOR":
            saw_return_generator = True
        elif saw_return_generator and instruction.opname == "RESUME":
            return index + 1
    return None


def _resume_suspended_generator(
    state: VMState,
    ctx: OpcodeDispatcher,
    generator: ModeledGenerator,
    request: _ResumeRequest,
    sent: StackValue | None,
    resume_pc: int | None = None,
) -> OpcodeResult:
    """Re-enter a suspended generator frame with *sent* on its stack."""
    if (
        generator.suspended_locals is None
        or generator.resume_pc is None
        or not generator.instructions
    ):
        return _abstract_generator_call(state)
    caller_instruction = ctx.get_instruction(state.pc)
    frame = CallFrame(
        function_name=generator.name,
        return_pc=state.pc + 1 if resume_pc is None else resume_pc,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_stack=tuple(state.stack),
        caller_instructions=cast("list[object]", list(ctx.instructions)),
        protocol_method=GENERATOR_RESUME_PROTOCOL,
        protocol_retained_operand=cast("StackValue", request),
        caller_offset=caller_instruction.offset if caller_instruction is not None else None,
    )
    instructions = list(generator.instructions)
    state = state.push_call(frame)
    state.local_vars = generator.suspended_locals.cow_fork()
    state.stack = [*generator.suspended_stack, sent]
    state.current_instructions = cast("list[object]", instructions)
    ctx.register_exception_entries(instructions, list(generator.exception_entries))
    ctx.set_instructions(instructions)
    state = state.set_pc(generator.resume_pc)
    state.depth += 1
    state.invalidate_cached_hash()
    return OpcodeResult.continue_with(state)


def _restore_caller(state: VMState, ctx: OpcodeDispatcher, frame: CallFrame) -> None:
    """Restore caller stack, locals, and bytecode after generator suspension."""
    from pysymex.execution.opcodes.common.control.returns import (
        apply_argument_alias_updates,
        restore_caller_stack,
    )

    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    if frame.caller_instructions is not None:
        instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", instructions)
        ctx.set_instructions(instructions)


def _replace_generator_aliases(
    state: VMState,
    old: ModeledGenerator,
    new: ModeledGenerator,
) -> None:
    """Replace *old* generator references in locals, globals, and the stack."""
    for name, value in tuple(state.local_vars.items()):
        state = state.set_local(str(name), cast("StackValue", _replace_value(value, old, new)))
    for name, value in tuple(state.global_vars.items()):
        state = state.set_global(str(name), cast("StackValue", _replace_value(value, old, new)))
    state.stack = [cast("StackValue", _replace_value(value, old, new)) for value in state.stack]
    state.invalidate_cached_hash()


def _replace_value(value: object, old: ModeledGenerator, new: ModeledGenerator) -> object:
    """Recursively substitute *new* for *old* inside nested container values."""
    _replace_context_manager_generator(value, old, new)
    if value is old:
        return new
    if isinstance(value, ModeledGenerator) and value.identity == old.identity:
        return new
    from pysymex.core.types.containers.sequences import SymbolicIterator

    if isinstance(value, SymbolicIterator) and value.iterable is old:
        return dataclasses.replace(value, iterable=new)
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


def _replace_context_manager_generator(
    value: object,
    old: ModeledGenerator,
    new: ModeledGenerator,
) -> None:
    """Update modeled ``contextlib.contextmanager`` receivers retained by bound methods."""
    from pysymex.models.stdlib.contextlib.managers import ContextManager

    candidates = (
        value,
        getattr(value, "__self__", None),
        getattr(value, "_modeled_object", None),
        getattr(value, "value", None),
    )
    for candidate in candidates:
        if isinstance(candidate, ContextManager):
            candidate.replace_modeled_generator(old, new)


def _complete_closed_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    request: _ResumeRequest,
) -> OpcodeResult:
    """Finish ``next``/``send`` on a closed generator with default or ``StopIteration``."""
    if request.has_default:
        value = request.default if request.default is not None else SymbolicNone()
        return OpcodeResult.continue_with(state.push(value).advance_pc())
    frame = CallFrame(
        "", state.pc + 1, state.local_vars, len(state.stack), caller_offset=instr.offset
    )
    return _raise_stop_iteration(state, ctx, frame)


def _complete_closed_for_iter(state: VMState, target_index: int) -> OpcodeResult:
    """Exit a ``FOR_ITER`` loop over a generator known to be closed."""
    return OpcodeResult.continue_with(state.set_pc(target_index).push(SymbolicNone()))


def _close_generator_call(state: VMState, generator: ModeledGenerator) -> OpcodeResult:
    """Close a generator without modeling ``GeneratorExit``/``finally`` execution."""
    fallback_event = unsupported_generator_event(
        state=state,
        reason="generator close finalization is not modeled precisely",
    )
    closed = dataclasses.replace(generator, closed=True)
    _replace_generator_aliases(state, generator, closed)
    state = state.push(SymbolicNone()).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )


def _raise_stop_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
    return_value: object | None = None,
) -> OpcodeResult:
    """Route or report ``StopIteration`` when a generator is exhausted."""
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


def _abstract_generator_call(state: VMState) -> OpcodeResult:
    """Havoc a generator resume result when precise continuation is unsupported."""
    fallback_event = unsupported_generator_event(
        state=state,
        reason="generator resume could not be modeled precisely",
    )
    value, constraint = HavocValue.havoc(f"havoc_generator_next_{state.pc}")
    state = state.push(value).add_constraint(constraint).advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[UNSUPPORTED_GENERATOR],
        fallback_events=[fallback_event],
    )
