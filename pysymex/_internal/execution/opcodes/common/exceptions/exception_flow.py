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

"""Exception handler flow for ``SETUP_FINALLY``, ``RAISE``, and handler jump opcodes.

Locates exception table entries, validates stack depth before handler transitions, and
builds forked states that enter ``except`` / ``finally`` blocks with symbolic exception
values. Used across :mod:`pysymex._internal.execution.opcodes.common.exceptions`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.exceptions.policy import concrete_exception
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.exceptions.classes import raised_exception_class

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _is_generator_close_completion(frame: CallFrame, exc: StackValue) -> bool:
    if frame.protocol_method != "__generator_resume__":
        return False
    request = frame.protocol_retained_operand
    if getattr(request, "operation", None) != "close":
        return False
    raised_type = raised_exception_class(exc)
    return raised_type is not None and issubclass(raised_type, (GeneratorExit, StopIteration))


def _complete_generator_close_exception(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    exc: StackValue,
) -> VMState | None:
    """Finish ``generator.close()`` when ``GeneratorExit``/``StopIteration`` escapes."""
    if not _is_generator_close_completion(frame, exc):
        return None
    request = frame.protocol_retained_operand

    from pysymex._internal.execution.opcodes.common.control.returns.state import (
        apply_argument_alias_updates,
        restore_caller_stack,
    )

    restore_caller_stack(state, frame)
    state.local_vars = apply_argument_alias_updates(state, frame)
    state.depth = max(0, state.depth - 1)
    if frame.caller_instructions is not None:
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", caller_instructions)
        ctx.set_instructions(caller_instructions)

    generator = getattr(request, "generator", None)
    if generator is not None:
        import dataclasses

        from pysymex._internal.execution.opcodes.common.generators.aliases import (
            replace_generator_aliases,
        )

        replace_generator_aliases(state, generator, dataclasses.replace(generator, closed=True))
    return state.set_pc(frame.return_pc).push(SymbolicNoneType())


def _convert_escaping_generator_stop_iteration(
    frame: CallFrame,
    exc: StackValue,
    raised_at: int,
) -> StackValue:
    """Apply PEP 479 when ``StopIteration`` escapes a resumed generator frame."""
    if frame.protocol_method != "__generator_resume__":
        return exc
    raised_type = raised_exception_class(exc)
    if raised_type is None or not issubclass(raised_type, (StopIteration, StopAsyncIteration)):
        return exc
    return concrete_exception(
        RuntimeError,
        "generator raised StopIteration",
        raised_at=raised_at,
    )


def _continue_chained_getattr(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    protocol_method: str,
) -> VMState:
    """Start a retained ``__getattr__`` call after primary lookup failed."""
    if len(frame.protocol_fallbacks) != 1:
        msg = "Chained getattr continuation requires one retained fallback"
        raise VMStateError(msg)
    candidate = frame.protocol_fallbacks[0]
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    method = lookup_modeled_method(candidate.owner, candidate.method_name)
    if method is None:
        msg = "Chained getattr continuation lost its retained __getattr__ method"
        raise VMStateError(msg)
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [candidate.argument],
        {},
        protocol_method=protocol_method,
        resume_pc=frame.return_pc,
        protocol_retained_operand=frame.protocol_retained_operand,
        caller_instructions_override=(
            list(frame.caller_instructions) if frame.caller_instructions is not None else None
        ),
        caller_offset_override=frame.caller_offset,
    )
    if result is None or result.terminal or len(result.new_states) != 1:
        msg = "Unable to execute chained getattr continuation"
        raise VMStateError(msg)
    return result.new_states[0]


class ExceptionFlow:
    """Domain owner for exception-table lookup and handler transitions."""

    @staticmethod
    def require_depth(
        state: VMState,
        instr: dis.Instruction,
        required_depth: int,
        purpose: str,
    ) -> None:
        """Enforce minimum stack depth for opcode execution."""
        if len(state.stack) < required_depth:
            msg = (
                f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
                f"cannot satisfy {required_depth} item(s) for {purpose}"
            )
            raise VMStateError(
                msg,
            )

    @staticmethod
    def entry_at(ctx: OpcodeDispatcher, offset: int) -> object | None:
        """Return the CPython exception-table entry covering *offset*."""
        entries = getattr(ctx, "_exception_entries", ())
        best_entry: object | None = None
        best_start: int | None = None
        best_end: int | None = None
        for entry in entries:
            start = getattr(entry, "start", None)
            end = getattr(entry, "end", None)
            target = getattr(entry, "target", None)
            if start is None or end is None or target is None:
                continue
            if start <= offset < end:
                if best_start is None:
                    best_entry = entry
                    best_start = start
                    best_end = end
                    continue
                if start > best_start:
                    best_entry = entry
                    best_start = start
                    best_end = end
                    continue
                if start == best_start and best_end is not None and end < best_end:
                    best_entry = entry
                    best_end = end
        return best_entry

    @staticmethod
    def is_handler_at(ctx: OpcodeDispatcher, offset: int) -> bool:
        """Return whether *offset* is an exception-table handler entry point."""
        entries = getattr(ctx, "_exception_entries", ())
        for entry in entries:
            target = getattr(entry, "target", None)
            if target == offset:
                return True
        return False

    @staticmethod
    def jump_to_handler(
        state: VMState,
        ctx: OpcodeDispatcher,
        offset: int,
        exc: StackValue,
        *,
        allow_unwind: bool = True,
    ) -> VMState | None:
        """Construct the stack shape CPython expects at an exception handler."""
        entry = ExceptionFlow.entry_at(ctx, offset)
        if entry is None:
            return (
                ExceptionFlow.unwind_interprocedural_exception(state, ctx, exc)
                if allow_unwind and state.call_stack
                else None
            )
        target = getattr(entry, "target", None)
        if target is None:
            return (
                ExceptionFlow.unwind_interprocedural_exception(state, ctx, exc)
                if allow_unwind and state.call_stack
                else None
            )
        handler_pc = ctx.offset_to_index(int(target))
        if handler_pc is None:
            return (
                ExceptionFlow.unwind_interprocedural_exception(state, ctx, exc)
                if allow_unwind and state.call_stack
                else None
            )

        depth_obj = getattr(entry, "depth", 0)
        depth = depth_obj if isinstance(depth_obj, int) and depth_obj > 0 else 0
        preserved = list(state.stack[:depth])

        next_state = state.set_pc(handler_pc)
        next_state.stack = type(state.stack)(preserved)
        next_state = next_state.push(exc)
        if bool(getattr(entry, "lasti", False)):
            next_state = next_state.push(SymbolicValue.from_const(offset))
        return next_state

    @staticmethod
    def unwind_interprocedural_exception(
        state: VMState,
        ctx: OpcodeDispatcher,
        exc: StackValue,
    ) -> VMState | None:
        """Propagate an uncaught callee exception through suspended caller frames."""
        from pysymex._internal.execution.opcodes.common.control.returns.state import (
            apply_argument_alias_updates,
            restore_caller_stack,
        )

        while (frame := state.pop_call()) is not None:
            close_completion = _complete_generator_close_exception(frame, state, ctx, exc)
            if close_completion is not None:
                return close_completion
            exc = _convert_escaping_generator_stop_iteration(frame, exc, state.pc)
            if frame.has_contract_frame and state.contract_frames:
                state.contract_frames.pop()
            restore_caller_stack(state, frame)
            state.local_vars = apply_argument_alias_updates(state, frame)
            state.depth = max(0, state.depth - 1)
            if frame.caller_instructions is None or frame.caller_offset is None:
                continue
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)
            from pysymex._internal.execution.opcodes.common.control.iteration.callable.sentinel import (
                finish_callable_sentinel_stop,
            )
            from pysymex._internal.execution.opcodes.common.control.iteration.sequence import (
                finish_getitem_index_error,
                finish_next_stop,
            )

            next_exit = finish_next_stop(frame, state, exc)
            if next_exit is not None:
                return next_exit
            callable_sentinel_exit = finish_callable_sentinel_stop(
                frame,
                state,
                exc,
            )
            if callable_sentinel_exit is not None:
                return callable_sentinel_exit
            sequence_exit = finish_getitem_index_error(frame, state, exc)
            if sequence_exit is not None:
                return sequence_exit
            default_state = ExceptionFlow.getattr_default(frame, state, ctx, exc)
            if default_state is not None:
                return default_state
            handler_state = ExceptionFlow.jump_to_handler(
                state,
                ctx,
                frame.caller_offset,
                exc,
                allow_unwind=False,
            )
            if handler_state is not None:
                return handler_state
        return None

    @staticmethod
    def getattr_default(
        frame: CallFrame,
        state: VMState,
        ctx: OpcodeDispatcher,
        exc: StackValue,
    ) -> VMState | None:
        """Resume a supported getattr hook after an AttributeError primary lookup."""
        from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.constants import (
            GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS,
            GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS,
            GETATTR_DEFAULT_PROTOCOL_METHODS,
        )

        exc_payload = getattr(exc, "_modeled_object", exc)
        exc_type = getattr(exc_payload, "exc_type", None)
        supported_protocols = (
            GETATTR_DEFAULT_PROTOCOL_METHODS | GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS
        )
        if frame.protocol_method not in supported_protocols or not (
            isinstance(exc_type, type) and issubclass(exc_type, AttributeError)
        ):
            if isinstance(exc_type, type) and issubclass(exc_type, AttributeError):
                from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import (
                    MatchPatternOps,
                )

                return MatchPatternOps.class_attr_error(frame, state)
            return None
        if frame.protocol_method in GETATTR_ATTRIBUTE_ERROR_CHAIN_PROTOCOL_METHODS:
            return _continue_chained_getattr(
                frame,
                state,
                ctx,
                protocol_method=(
                    "__getattr_default__"
                    if frame.protocol_method in GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS
                    else "__getattr__"
                ),
            )
        default_value = frame.protocol_retained_operand
        if default_value is None:
            default_value = SymbolicNoneType("getattr_default_None")
        return state.set_pc(frame.return_pc).push(default_value)
