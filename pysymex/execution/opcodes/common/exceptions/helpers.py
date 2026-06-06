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

"""Shared helpers for ``SETUP_FINALLY``, ``RAISE``, and handler jump opcodes.

Locates exception table entries, validates stack depth before handler transitions, and
builds forked states that enter ``except`` / ``finally`` blocks with symbolic exception
values. Used across :mod:`pysymex.execution.opcodes.common.exceptions`.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, TypeGuard, cast

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.types import VMStateError
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def find_exception_entry(ctx: OpcodeDispatcher, offset: int) -> object | None:
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


def is_exception_handler_target(ctx: OpcodeDispatcher, offset: int) -> bool:
    """Return whether *offset* is an exception-table handler entry point."""
    entries = getattr(ctx, "_exception_entries", ())
    for entry in entries:
        target = getattr(entry, "target", None)
        if target == offset:
            return True
    return False


def jump_to_exception_handler(
    state: VMState,
    ctx: OpcodeDispatcher,
    offset: int,
    exc: StackValue,
    *,
    allow_unwind: bool = True,
) -> VMState | None:
    """Construct the stack shape CPython expects at an exception handler."""
    entry = find_exception_entry(ctx, offset)
    if entry is None:
        return (
            unwind_interprocedural_exception(state, ctx, exc)
            if allow_unwind and state.call_stack
            else None
        )
    target = getattr(entry, "target", None)
    if target is None:
        return (
            unwind_interprocedural_exception(state, ctx, exc)
            if allow_unwind and state.call_stack
            else None
        )
    handler_pc = ctx.offset_to_index(int(target))
    if handler_pc is None:
        return (
            unwind_interprocedural_exception(state, ctx, exc)
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


def unwind_interprocedural_exception(
    state: VMState,
    ctx: OpcodeDispatcher,
    exc: StackValue,
) -> VMState | None:
    """Propagate an uncaught callee exception through suspended caller frames."""
    from pysymex.execution.opcodes.common.control.returns import (
        apply_argument_alias_updates,
        restore_caller_stack,
    )

    while (frame := state.pop_call()) is not None:
        exc = _convert_escaping_generator_stop_iteration(frame, exc, state.pc)
        if state.contract_frames:
            state.contract_frames.pop()
        restore_caller_stack(state, frame)
        state.local_vars = apply_argument_alias_updates(state, frame)
        state.depth = max(0, state.depth - 1)
        if frame.caller_instructions is None or frame.caller_offset is None:
            continue
        caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
        state.current_instructions = cast("list[object]", caller_instructions)
        ctx.set_instructions(caller_instructions)
        from pysymex.execution.opcodes.common.control.sequence_iteration import (
            complete_next_iteration_stop_iteration,
            complete_sequence_getitem_iteration_index_error,
        )
        from pysymex.execution.opcodes.common.control.callable_sentinel_iteration import (
            complete_callable_sentinel_iteration_stop_iteration,
        )

        next_exit = complete_next_iteration_stop_iteration(frame, state, exc)
        if next_exit is not None:
            return next_exit
        callable_sentinel_exit = complete_callable_sentinel_iteration_stop_iteration(
            frame,
            state,
            exc,
        )
        if callable_sentinel_exit is not None:
            return callable_sentinel_exit
        sequence_exit = complete_sequence_getitem_iteration_index_error(frame, state, exc)
        if sequence_exit is not None:
            return sequence_exit
        default_state = complete_getattr_default_after_attribute_error(frame, state, ctx, exc)
        if default_state is not None:
            return default_state
        handler_state = jump_to_exception_handler(
            state, ctx, frame.caller_offset, exc, allow_unwind=False
        )
        if handler_state is not None:
            return handler_state
    return None


def _convert_escaping_generator_stop_iteration(
    frame: CallFrame,
    exc: StackValue,
    raised_at: int,
) -> StackValue:
    """Apply PEP 479 when ``StopIteration`` escapes a resumed generator frame."""
    if frame.protocol_method != "__generator_resume__":
        return exc
    raised_type = _raised_exception_class(exc)
    if raised_type is None or not issubclass(raised_type, (StopIteration, StopAsyncIteration)):
        return exc
    return SymbolicException.concrete(
        RuntimeError,
        "generator raised StopIteration",
        raised_at=raised_at,
    )


def complete_getattr_default_after_attribute_error(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
    exc: StackValue,
) -> VMState | None:
    """Resume a supported three-argument getattr hook with its retained default."""
    from pysymex.execution.opcodes.common.functions.attribute.protocols import (
        GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS,
        GETATTR_DEFAULT_PROTOCOL_METHODS,
    )

    exc_payload = getattr(exc, "_modeled_object", exc)
    exc_type = getattr(exc_payload, "exc_type", None)
    if frame.protocol_method not in GETATTR_DEFAULT_PROTOCOL_METHODS or not (
        isinstance(exc_type, type) and issubclass(exc_type, AttributeError)
    ):
        return None
    if frame.protocol_method in GETATTR_CHAINED_DEFAULT_PROTOCOL_METHODS:
        return _continue_chained_getattr_default(frame, state, ctx)
    default_value = frame.protocol_retained_operand
    if default_value is None:
        default_value = SymbolicNone("getattr_default_None")
    return state.set_pc(frame.return_pc).push(default_value)


def _continue_chained_getattr_default(
    frame: CallFrame,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> VMState:
    """Start a retained ``__getattr__`` call after primary lookup failed."""
    if len(frame.protocol_fallbacks) != 1:
        raise VMStateError("Chained getattr continuation requires one retained fallback")
    candidate = frame.protocol_fallbacks[0]
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(candidate.owner, candidate.method_name)
    if method is None:
        raise VMStateError("Chained getattr continuation lost its retained __getattr__ method")
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [candidate.argument],
        {},
        protocol_method="__getattr_default__",
        resume_pc=frame.return_pc,
        protocol_retained_operand=frame.protocol_retained_operand,
    )
    if result is None or result.terminal or len(result.new_states) != 1:
        raise VMStateError("Unable to execute chained getattr continuation")
    return result.new_states[0]


_MISSING_ITEMS = object()


def concrete_exception_match(exc: object, exc_types: list[object]) -> bool | None:
    """Return a precise CPython-style subclass match when all classes are known."""
    raised_type = _raised_exception_class(exc)
    if raised_type is None:
        return None

    handler_types: list[type[BaseException]] = []
    for exc_type in exc_types:
        handler_type = _handler_exception_class(exc_type)
        if handler_type is None:
            return None
        handler_types.append(handler_type)

    return any(issubclass(raised_type, handler_type) for handler_type in handler_types)


def has_definite_invalid_exception_handler(exc_types: list[object]) -> bool:
    """Return true when a handler target is definitely invalid for ``except``."""
    return any(_is_definite_invalid_exception_handler(exc_type) for exc_type in exc_types)


def _is_definite_invalid_exception_handler(value: object) -> bool:
    """Return whether ``value`` is known not to be a valid exception handler target."""
    if _handler_exception_class(value) is not None:
        return False
    if _symbolic_exception_payload(value) is not None:
        return False
    return not isinstance(value, SymbolicValue)


def _raised_exception_class(value: object) -> type[BaseException] | None:
    """Resolve the concrete class of a raised exception value when available."""
    payload = _symbolic_exception_payload(value)
    if payload is not None:
        exc_type = payload.exc_type
        if isinstance(exc_type, type):
            return exc_type
        return None
    if isinstance(value, BaseException):
        return type(value)
    if _is_base_exception_class(value):
        return value
    return None


def _handler_exception_class(value: object) -> type[BaseException] | None:
    """Resolve a concrete exception handler class without accepting instances."""
    if _is_base_exception_class(value):
        return value
    payload = _symbolic_exception_payload(value)
    if payload is None:
        return None
    exc_type = payload.exc_type
    if isinstance(exc_type, type):
        return exc_type
    return None


def _is_base_exception_class(value: object) -> TypeGuard[type[BaseException]]:
    """Return whether ``value`` is a concrete ``BaseException`` subclass."""
    return isinstance(value, type) and issubclass(value, BaseException)


def _symbolic_exception_payload(value: object) -> SymbolicException | None:
    """Extract a symbolic exception from a direct value or modeled wrapper."""
    if isinstance(value, SymbolicException):
        return value
    modeled_value = getattr(value, "_modeled_object", None)
    return modeled_value if isinstance(modeled_value, SymbolicException) else None


def materialize_exception_items(exc_types_obj: object) -> list[object]:
    """Normalize exception type payloads to a plain list."""
    raw_items_attr = getattr(exc_types_obj, "_concrete_items", _MISSING_ITEMS)
    if raw_items_attr is not _MISSING_ITEMS:
        if raw_items_attr is None:
            return []
        if isinstance(raw_items_attr, tuple):
            return list(cast("tuple[object, ...]", raw_items_attr))
        if isinstance(raw_items_attr, list):
            return list(cast("list[object]", raw_items_attr))
        return [raw_items_attr]

    raw_items_obj: object = exc_types_obj
    if raw_items_obj is None:
        return []
    if isinstance(raw_items_obj, tuple):
        return list(cast("tuple[object, ...]", raw_items_obj))
    return [raw_items_obj]


__all__ = [
    "complete_getattr_default_after_attribute_error",
    "concrete_exception_match",
    "find_exception_entry",
    "has_definite_invalid_exception_handler",
    "is_exception_handler_target",
    "jump_to_exception_handler",
    "materialize_exception_items",
    "require_stack_depth",
    "unwind_interprocedural_exception",
]
