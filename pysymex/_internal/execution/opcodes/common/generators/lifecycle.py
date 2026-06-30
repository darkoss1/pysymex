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
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.types import CallFrame
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.iteration.exit import (
    push_for_iter_exit_sentinel,
)
from pysymex._internal.execution.opcodes.common.generators.aliases import (
    latest_generator_alias,
    replace_generator_aliases,
)
from pysymex._internal.execution.opcodes.common.generators.requests import (
    GENERATOR_RESUME_PROTOCOL,
    ResumeRequest,
    request_for_frame,
    resume_request_from_call,
)
from pysymex._internal.execution.opcodes.common.generators.results import (
    abstract_generator_call,
    close_generator_call,
    complete_closed_call,
    complete_closed_for_iter,
    raise_stop_iteration,
    type_error_result,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


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
    request, sent = resume_request_from_call(func_obj, args, kwargs)
    if request is None:
        return None
    generator = latest_generator_alias(state, request.generator)
    if generator is not request.generator:
        request = dataclasses.replace(request, generator=generator)
    if request.operation == "close":
        return _close_generator_call(state, ctx, instr, generator)
    if request.operation == "throw":
        return abstract_generator_call(state)
    if generator.closed:
        return complete_closed_call(state, ctx, instr, request)
    if not generator.started:
        if sent is not None:
            return type_error_result(
                state,
                ctx,
                instr,
                "can't send non-None value to a just-started generator",
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
    push_exit_sentinel: bool = True,
    pop_exit_iterator: bool = False,
) -> OpcodeResult:
    """Resume a generator for ``FOR_ITER`` while preserving loop-exit semantics."""
    if generator.closed:
        return complete_closed_for_iter(
            state,
            target_index,
            push_exit_sentinel=push_exit_sentinel,
            pop_exit_iterator=pop_exit_iterator,
        )

    request = ResumeRequest(
        generator,
        for_iter_exit_pc=target_index,
        push_for_iter_exit_sentinel=push_exit_sentinel,
        pop_for_iter_exit_iterator=pop_exit_iterator,
    )
    if not generator.started:
        return _start_generator(state, ctx, generator, request, resume_pc=continue_pc)
    return _resume_suspended_generator(state, ctx, generator, request, None, resume_pc=continue_pc)


def resume_generator_yield_from_send(
    state: VMState,
    ctx: OpcodeDispatcher,
    generator: ModeledGenerator,
    sent: StackValue | None,
    *,
    target_index: int | None,
    continue_pc: int,
) -> OpcodeResult:
    """Resume a subgenerator for CPython ``yield from`` ``SEND`` semantics."""
    if generator.closed:
        state = state.push(SymbolicNoneType())
        state = state.set_pc(target_index) if target_index is not None else state.advance_pc()
        return OpcodeResult.continue_with(state)

    request = ResumeRequest(generator, yield_from_return_pc=target_index)
    if not generator.started:
        if sent is not None and not isinstance(sent, SymbolicNoneType):
            return abstract_generator_call(state)
        return _start_generator(state, ctx, generator, request, resume_pc=continue_pc)
    return _resume_suspended_generator(state, ctx, generator, request, sent, resume_pc=continue_pc)


def suspend_generator_yield_or_abstract(
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Suspend an executing modeled generator, or retain abstract yield behavior."""
    frame = state.call_stack[-1] if state.call_stack else None
    request = request_for_frame(frame)
    if frame is None or request is None:
        state.pop()
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        sent, constraint = SymbolicValue.symbolic(f"yield_sent_{state.pc}")
        return OpcodeResult.continue_with(state.push(sent).add_constraint(constraint).advance_pc())
    if request.operation == "close":
        return _generator_close_yield_error(state, ctx, frame, request)

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
    replace_generator_aliases(state, request.generator, updated)
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
    request = request_for_frame(frame)
    if request is None:
        return None
    if request.operation == "close":
        closed = dataclasses.replace(request.generator, closed=True)
        _restore_caller(state, ctx, frame)
        replace_generator_aliases(state, request.generator, closed)
        state.depth = max(0, state.depth - 1)
        return OpcodeResult.continue_with(state.set_pc(frame.return_pc).push(SymbolicNoneType()))
    closed = dataclasses.replace(request.generator, closed=True)
    _restore_caller(state, ctx, frame)
    replace_generator_aliases(state, request.generator, closed)
    state.depth = max(0, state.depth - 1)
    if request.for_iter_exit_pc is not None:
        exit_state = push_for_iter_exit_sentinel(
            state,
            name="generator_iter_exhausted",
            push_sentinel=request.push_for_iter_exit_sentinel,
            pop_iterator=request.pop_for_iter_exit_iterator,
        )
        return OpcodeResult.continue_with(exit_state.set_pc(request.for_iter_exit_pc))
    if request.yield_from_return_pc is not None:
        result = (
            cast("StackValue", return_value) if return_value is not None else SymbolicNoneType()
        )
        return OpcodeResult.continue_with(state.set_pc(request.yield_from_return_pc).push(result))
    if request.has_default:
        default = request.default if request.default is not None else SymbolicNoneType()
        return OpcodeResult.continue_with(state.set_pc(frame.return_pc).push(default))
    return raise_stop_iteration(state, ctx, frame, return_value)


def _start_generator(
    state: VMState,
    ctx: OpcodeDispatcher,
    generator: ModeledGenerator,
    request: ResumeRequest,
    resume_pc: int | None = None,
) -> OpcodeResult:
    """Enter a cold modeled generator via interprocedural call."""
    from pysymex._internal.execution.calls.interprocedural.entry import (
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
        return abstract_generator_call(state)
    next_state = result.new_states[0]
    first_body_pc = _first_body_pc(ctx.instructions)
    if first_body_pc is None:
        return abstract_generator_call(state)
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
    request: ResumeRequest,
    sent: StackValue | None,
    resume_pc: int | None = None,
) -> OpcodeResult:
    """Re-enter a suspended generator frame with *sent* on its stack."""
    if (
        generator.suspended_locals is None
        or generator.resume_pc is None
        or not generator.instructions
    ):
        return abstract_generator_call(state)
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


def _close_generator_call(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    generator: ModeledGenerator,
) -> OpcodeResult:
    """Inject ``GeneratorExit`` into a suspended generator for ``close()``."""
    if generator.closed or not generator.started:
        closed = dataclasses.replace(generator, closed=True)
        replace_generator_aliases(state, generator, closed)
        return OpcodeResult.continue_with(state.push(SymbolicNoneType()).advance_pc())
    if (
        generator.suspended_locals is None
        or generator.resume_pc is None
        or not generator.instructions
    ):
        return close_generator_call(state, generator)

    yield_index = generator.resume_pc - 1
    instructions = list(generator.instructions)
    if not (0 <= yield_index < len(instructions)):
        return close_generator_call(state, generator)

    frame = CallFrame(
        function_name=generator.name,
        return_pc=state.pc + 1,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_stack=tuple(state.stack),
        caller_instructions=cast("list[object]", list(ctx.instructions)),
        protocol_method=GENERATOR_RESUME_PROTOCOL,
        protocol_retained_operand=cast(
            "StackValue",
            ResumeRequest(generator, operation="close"),
        ),
        caller_offset=instr.offset,
    )
    state = state.push_call(frame)
    state.local_vars = generator.suspended_locals.cow_fork()
    state.stack = [*generator.suspended_stack]
    state.current_instructions = cast("list[object]", instructions)
    ctx.register_exception_entries(instructions, list(generator.exception_entries))
    ctx.set_instructions(instructions)
    state.depth += 1
    state.invalidate_cached_hash()

    from pysymex._internal.core.exceptions.policy import generator_exit
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    yield_offset = instructions[yield_index].offset
    exc = generator_exit(raised_at=yield_offset)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, yield_offset, exc, allow_unwind=False)
    if handler_state is None:
        state.pop_call()
        _restore_caller(state, ctx, frame)
        closed = dataclasses.replace(generator, closed=True)
        replace_generator_aliases(state, generator, closed)
        state.depth = max(0, state.depth - 1)
        return OpcodeResult.continue_with(state.set_pc(frame.return_pc).push(SymbolicNoneType()))
    return OpcodeResult.continue_with(handler_state)


def _generator_close_yield_error(
    state: VMState,
    ctx: OpcodeDispatcher,
    frame: CallFrame,
    request: ResumeRequest,
) -> OpcodeResult:
    """Raise CPython's ``generator ignored GeneratorExit`` close error."""
    from pysymex._internal.analysis.detectors.detector.types import Issue, IssueKind
    from pysymex._internal.core.exceptions.policy import concrete_exception
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    state.pop()
    exc = concrete_exception(
        RuntimeError,
        "generator ignored GeneratorExit",
        raised_at=frame.caller_offset or state.pc,
    )
    state.pop_call()
    _restore_caller(state, ctx, frame)
    state.depth = max(0, state.depth - 1)

    if frame.caller_offset is not None:
        handled = ExceptionFlow.jump_to_handler(state, ctx, frame.caller_offset, exc)
        if handled is not None:
            handled.deferred_detector_issues = []
            handled.invalidate_cached_hash()
            return OpcodeResult.continue_with(handled)

    state.deferred_detector_issues = []
    state.invalidate_cached_hash()
    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION,
        message="Path raises unhandled exception: RuntimeError: generator ignored GeneratorExit",
        constraints=list(state.path_constraints),
        pc=exc.raised_at,
    )
    return OpcodeResult.error(issue)


def _restore_caller(state: VMState, ctx: OpcodeDispatcher, frame: CallFrame) -> None:
    """Restore caller stack, locals, and bytecode after generator suspension."""
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
