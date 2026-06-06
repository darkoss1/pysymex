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

"""Continuation helpers for CPython iterator protocol fallbacks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions.protocol.fallbacks import (
    ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    UNSUPPORTED_ITERATION_PROTOCOL,
    unsupported_iteration_event,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.core.state.types import CallFrame
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher

SEQUENCE_GETITEM_ITER_PROTOCOL = "__getitem_iter__"
NEXT_ITER_PROTOCOL = "__next_iter__"
_BUILTIN_EXCEPTION_CLASSES: dict[str, type[BaseException]] = {
    "IndexError": IndexError,
    "StopIteration": StopIteration,
}


@dataclass(frozen=True, slots=True)
class SequenceIterationContinuation:
    """Caller-loop state retained while a modeled ``__getitem__`` executes."""

    iterator: SymbolicIterator
    target_index: int
    continue_pc: int


@dataclass(frozen=True, slots=True)
class NextIterationContinuation:
    """Caller-loop state retained while a modeled ``__next__`` executes."""

    target_index: int


def dispatch_sequence_getitem_iteration(
    state: VMState,
    ctx: OpcodeDispatcher,
    iterator: SymbolicIterator,
    iterable: StackValue,
    *,
    target_index: int,
) -> OpcodeResult | None:
    """Enter ``iterable.__getitem__(iterator.index)`` for CPython sequence iteration."""
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    method = lookup_modeled_method(iterable, "__getitem__")
    if method is None:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    result = perform_interprocedural_call_impl(
        state,
        ctx,
        method,
        [iterable, cast("StackValue", iterator.index)],
        {},
        protocol_method=SEQUENCE_GETITEM_ITER_PROTOCOL,
        resume_pc=state.pc,
        protocol_retained_operand=cast(
            "StackValue",
            SequenceIterationContinuation(
                iterator=iterator,
                target_index=target_index,
                continue_pc=state.pc + 1,
            ),
        ),
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_ITERATION_PROTOCOL],
        fallback_events=[
            unsupported_iteration_event(
                state=state,
                reason=ITERATION_PROTOCOL_UNAVAILABLE_REASON,
            )
        ],
        terminal=True,
    )


def next_iteration_retained_operand(target_index: int) -> StackValue:
    """Return a typed retained operand for a modeled ``__next__`` loop call."""
    return cast("StackValue", NextIterationContinuation(target_index=target_index))


def complete_next_iteration_stop_iteration(
    frame: CallFrame,
    state: VMState,
    exc: StackValue,
) -> VMState | None:
    """Convert ``StopIteration`` from iterator ``__next__`` into ``FOR_ITER`` exit."""
    retained = _retained_next_iteration(frame)
    if retained is None or not _is_stop_iteration(exc):
        return None
    return state.push(SymbolicNone("next_iter_exhausted")).set_pc(retained.target_index)


def is_next_iteration_return(frame: CallFrame) -> bool:
    """Return whether a normal protocol return is a yielded iterator item."""
    return _retained_next_iteration(frame) is not None


def complete_sequence_getitem_iteration_return(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> OpcodeResult | None:
    """Push the returned sequence item and advance the retained iterator."""
    retained = _retained_sequence_iteration(frame)
    if retained is None:
        return None
    if state.stack:
        state.pop()
    item = return_value if return_value is not None else SymbolicNone("sequence_item_None")
    state = state.push(retained.iterator.advance())
    state = state.push(item)
    state = state.set_pc(retained.continue_pc)
    state.depth -= 1
    return OpcodeResult.continue_with(state)


def complete_sequence_getitem_iteration_index_error(
    frame: CallFrame,
    state: VMState,
    exc: StackValue,
) -> VMState | None:
    """Convert ``IndexError`` from sequence ``__getitem__`` into ``FOR_ITER`` exit."""
    retained = _retained_sequence_iteration(frame)
    if retained is None or not _is_index_error(exc):
        return None
    return state.push(SymbolicNone("sequence_iter_exhausted")).set_pc(retained.target_index)


def sequence_getitem_iteration_handles_exception(
    state: VMState,
    exception_name: str,
) -> bool:
    """Return whether an active sequence-iteration protocol consumes the exception."""
    return any(
        _retained_sequence_iteration(frame) is not None
        for frame in _iteration_frames_for_exception(state, exception_name, "IndexError")
    )


def next_iteration_handles_exception(
    state: VMState,
    exception_name: str,
) -> bool:
    """Return whether an active iterator ``__next__`` protocol consumes the exception."""
    return any(
        _retained_next_iteration(frame) is not None
        for frame in _iteration_frames_for_exception(state, exception_name, "StopIteration")
    )


def _retained_sequence_iteration(frame: CallFrame) -> SequenceIterationContinuation | None:
    """Return retained sequence iteration state for the active protocol frame."""
    if frame.protocol_method != SEQUENCE_GETITEM_ITER_PROTOCOL:
        return None
    retained = frame.protocol_retained_operand
    if isinstance(retained, SequenceIterationContinuation):
        return retained
    return None


def _retained_next_iteration(frame: CallFrame) -> NextIterationContinuation | None:
    """Return retained iterator-next state for the active protocol frame."""
    if frame.protocol_method != NEXT_ITER_PROTOCOL:
        return None
    retained = frame.protocol_retained_operand
    if isinstance(retained, NextIterationContinuation):
        return retained
    return None


def _iteration_frames_for_exception(
    state: VMState,
    exception_name: str,
    expected_name: str,
) -> list[CallFrame]:
    """Return active call frames if the exception name matches the protocol exit."""
    if _normalize_exception_name(exception_name) != expected_name:
        return []
    return list(state.call_stack)


def _is_index_error(exc: object) -> bool:
    """Return whether *exc* definitely denotes an ``IndexError``."""
    exc_type = _exception_class(exc)
    return exc_type is not None and issubclass(exc_type, IndexError)


def _is_stop_iteration(exc: object) -> bool:
    """Return whether *exc* definitely denotes ``StopIteration``."""
    exc_type = _exception_class(exc)
    return exc_type is not None and issubclass(exc_type, StopIteration)


def _normalize_exception_name(name: str) -> str:
    """Return a builtin exception name from symbolic global/load names."""
    if name.startswith("global_"):
        return name.removeprefix("global_")
    return name


def _exception_class(value: object) -> type[BaseException] | None:
    """Resolve direct, wrapped, or modeled exception classes used by opcode flow."""
    if isinstance(value, SymbolicValue):
        inner = value.value
        if isinstance(inner, type) and issubclass(inner, BaseException):
            return inner
        model_name = value.model_name or _normalize_exception_name(value.name)
        if model_name in _BUILTIN_EXCEPTION_CLASSES:
            return _BUILTIN_EXCEPTION_CLASSES[model_name]
    payload = value if isinstance(value, SymbolicException) else None
    if payload is None:
        modeled_value = getattr(value, "_modeled_object", None)
        payload = modeled_value if isinstance(modeled_value, SymbolicException) else None
    if payload is not None:
        exc_type = payload.exc_type
        if isinstance(exc_type, type):
            return exc_type
        return _BUILTIN_EXCEPTION_CLASSES.get(exc_type)
    if isinstance(value, BaseException):
        return type(value)
    if isinstance(value, type) and issubclass(value, BaseException):
        return value
    return None


__all__ = [
    "NEXT_ITER_PROTOCOL",
    "NextIterationContinuation",
    "SEQUENCE_GETITEM_ITER_PROTOCOL",
    "SequenceIterationContinuation",
    "complete_next_iteration_stop_iteration",
    "complete_sequence_getitem_iteration_index_error",
    "complete_sequence_getitem_iteration_return",
    "dispatch_sequence_getitem_iteration",
    "is_next_iteration_return",
    "next_iteration_handles_exception",
    "next_iteration_retained_operand",
    "sequence_getitem_iteration_handles_exception",
]
