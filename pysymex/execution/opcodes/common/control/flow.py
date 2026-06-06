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

"""Raise, intrinsic, iterator, and length handlers for common control opcodes.

Owns ``RAISE_VARARGS``, ``GET_LEN``, ``CALL_INTRINSIC_*``, and re-exports iterator
helpers from :mod:`pysymex.execution.opcodes.common.control.iteration`. Version
packages delegate here; does not own branch feasibility (see
:mod:`pysymex.execution.opcodes.common.control.feasibility`) or ``MATCH_*`` lowering.
"""

from __future__ import annotations

import dataclasses
import dis
from collections.abc import Sized
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    add_lowered_constraints,
    apply_heap_updates,
    as_stack_value,
    extract_concrete_sequence,
)
from pysymex.execution.opcodes.common.control.match_helpers import resolve_match_subject
from pysymex.execution.opcodes.common.control.iteration import (
    handle_common_for_iter as handle_common_for_iter,
    handle_common_get_iter as handle_common_get_iter,
)
from pysymex.execution.opcodes.common.control_fallbacks import (
    LIST_TO_TUPLE_TYPE_UNCERTAIN,
    list_to_tuple_type_uncertain_event,
)
from pysymex.execution.opcodes.common.lowering import CollectionLowerer
from pysymex.execution.opcodes.common.numeric.ops import continue_unary_positive_value

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


def handle_common_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Propagate an exception into the innermost ``except`` or ``finally`` handler.

    CPython stack effect: consumes ``argc`` operands plus the exception value (not
    modeled operand-by-operand here). Walks ``state.block_stack`` from the top;
    for each ``except``/``finally`` block with a ``handler_pc``, forks a successor
    that exits blocks up to that frame, pushes a fresh symbolic exception value, and
    records an unconstrained feasibility literal for it.

    Side Effects:
        May return :meth:`OpcodeResult.branch` with one fork per matching handler;
        terminates when no handler exists or the raised type is ``NotImplementedError``.

    Limitations:
        Does not model exception cause/context chains or ``raise`` re-raise semantics;
        symbolic exception types are not tied to the stack operands.
    """
    _argc = int(instr.argval) if instr.argval else 0
    is_not_implemented = False
    if state.stack:
        top = state.peek()
        top_name = str(getattr(top, "name", "") or getattr(top, "_name", "") or "")
        if "NotImplementedError" in top_name:
            is_not_implemented = True

    if is_not_implemented:
        return OpcodeResult.terminate()

    for idx, block in enumerate(reversed(state.block_stack)):
        actual_idx = len(state.block_stack) - 1 - idx
        if block.block_type in ("finally", "except"):
            exc_state = state.fork()
            while len(exc_state.block_stack) > actual_idx:
                exc_state.exit_block()

            exc_val, constraint = SymbolicValue.symbolic(f"exception_{state.pc}")
            exc_state = exc_state.push(exc_val)
            exc_state = exc_state.add_constraint(constraint)
            if block.handler_pc is None:
                continue
            exc_state = exc_state.set_pc(block.handler_pc)

            return OpcodeResult.branch([exc_state])

    return OpcodeResult.terminate()


def handle_common_get_len(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push a symbolic length for the TOS value used by ``MATCH_*`` and sequences.

    CPython stack effect: ``TOS -> TOS1`` (replaces subject with ``len(subject)``).
    Resolves pattern subjects via :func:`resolve_match_subject`; uses container
    ``z3_len`` for modeled lists/dicts/strings, concrete ``len`` for ``Sized``, or a
    fresh ``Int`` symbol otherwise. Always adds ``length >= 0`` to the path.

    Side Effects:
        Mutates stack in place on the continuing path; advances PC by one.

    Limitations:
        Unknown container kinds get an unconstrained length symbol without tying it
        to element count.
    """
    if state.stack:
        value = resolve_match_subject(state.peek(), state)
        if isinstance(value, (SymbolicList, SymbolicDict, SymbolicString)):
            length = value.z3_len
        elif isinstance(value, Sized):
            length = get_int_val(len(value))
        else:
            length = z3.Int(f"len_{state.pc}")
        result = SymbolicValue(
            _name=f"len_{state.pc}",
            z3_int=length,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )
        state = state.push(result)
        state = state.add_constraint(length >= 0)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_list_to_tuple_intrinsic(
    instr: dis.Instruction,
    state: VMState,
    arg: object,
) -> OpcodeResult:
    """Lower ``INTRINSIC_LIST_TO_TUPLE`` via concrete, modeled, or havoc tuple paths.

    CPython stack effect: consumes the list/tuple carrier and pushes a tuple. Concrete
    sequences use :class:`~pysymex.execution.opcodes.common.lowering.CollectionLowerer`
    with heap updates; ``SymbolicList`` is structurally reused as a tuple-shaped
    value; otherwise introduces a symbolic tuple and records
    ``LIST_TO_TUPLE_TYPE_UNCERTAIN`` degradation.

    Side Effects:
        May append lowered constraints and apply heap updates on the precise path.

    Limitations:
        Symbolic non-list payloads are not proven tuple-typed; havoc does not preserve
        per-element aliasing from the source list.
    """
    payload = _resolve_list_to_tuple_payload(state, arg)
    concrete_sequence = extract_concrete_sequence(payload)
    if concrete_sequence is not None:
        items = [as_stack_value(item) for item in concrete_sequence]
        lowerer = CollectionLowerer(state.pc)
        lowered = lowerer.build_tuple(items)
        state = add_lowered_constraints(state, lowered.constraints)
        state = apply_heap_updates(state, lowered.heap_updates)
        state = state.push(lowered.value)
        return OpcodeResult.continue_with(state.advance_pc())

    if isinstance(payload, SymbolicList):
        tuple_value = dataclasses.replace(payload, _name=f"tuple_{state.pc}")
        state = state.push(tuple_value)
        return OpcodeResult.continue_with(state.advance_pc())

    result, constraint = SymbolicValue.symbolic(f"tuple_{state.pc}")
    state = state.push(result)
    state = state.add_constraint(constraint)
    fallback_event = list_to_tuple_type_uncertain_event(state=state)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[LIST_TO_TUPLE_TYPE_UNCERTAIN],
        fallback_events=[fallback_event],
    )


def _resolve_list_to_tuple_payload(state: VMState, arg: object) -> object:
    """Resolve the heap or modeled sequence payload for list-to-tuple lowering."""
    if isinstance(arg, SymbolicObject) and arg.address != -1:
        return state.load_heap(arg.address, arg)
    if isinstance(arg, SymbolicValue):
        modeled_object = getattr(arg, "_modeled_object", None)
        if modeled_object is not None:
            return modeled_object
        value = arg.value
        if value is not None:
            return value
    return arg


def handle_common_call_intrinsic_1(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Dispatch ``CALL_INTRINSIC_1`` (Python 3.12+) by intrinsic id.

    CPython stack effect: pops one operand (when present) and pushes the intrinsic
    result. Handles ``None``/``Ellipsis`` pushes, generator ``StopIteration`` wrapper,
    unary-positive forwarding (intrinsic 5), list-to-tuple (6), typing placeholders
    (7–11), and a symbolic fallback for unknown ids.

    Side Effects:
        May delegate to :func:`continue_unary_positive_value` or
        :func:`handle_common_list_to_tuple_intrinsic`; otherwise adds feasibility
        literals for introduced symbols.

    Limitations:
        Typing and generic-alias intrinsics are symbolic stubs, not full ``typing``
        semantics.
    """
    arg = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id in (1, 2):
        state = state.push(SymbolicNone())
    elif intrinsic_id == 3:
        state = state.push(_stopiteration_error_value(state, state.pc))
    elif intrinsic_id == 4:
        wrapped, constraint = SymbolicValue.symbolic(f"async_gen_wrap_{state.pc}")
        state = state.push(wrapped)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 5:
        return continue_unary_positive_value(instr, state, ctx, arg)
    elif intrinsic_id == 6:
        return handle_common_list_to_tuple_intrinsic(instr, state, arg)
    elif intrinsic_id in (7, 8, 9):
        type_names = {7: "TypeVar", 8: "ParamSpec", 9: "TypeVarTuple"}
        type_val, constraint = SymbolicValue.symbolic(f"{type_names[intrinsic_id]}_{state.pc}")
        state = state.push(type_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 10:
        result, constraint = SymbolicValue.symbolic(f"generic_alias_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 11:
        alias_val, constraint = SymbolicValue.symbolic(f"type_alias_{state.pc}")
        state = state.push(alias_val)
        state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic1_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _stopiteration_error_value(state: VMState, pc: int) -> StackValue:
    """Return CPython's generator StopIteration wrapper result.

    ``INTRINSIC_STOPITERATION_ERROR`` sees the active exception below the lasti
    marker. CPython converts only StopIteration-family escapes to RuntimeError;
    unrelated exceptions are re-raised unchanged by the following RERAISE.
    """
    current_exception = state.peek() if state.stack else None
    payload = _symbolic_exception_payload(current_exception)
    exc_type: object
    if payload is not None:
        exc_type = payload.exc_type
    elif isinstance(current_exception, BaseException):
        exc_type = type(current_exception)
    elif isinstance(current_exception, type) and issubclass(current_exception, BaseException):
        exc_type = current_exception
    else:
        exc_type = None

    if isinstance(exc_type, type) and issubclass(exc_type, (StopIteration, StopAsyncIteration)):
        return SymbolicException.concrete(
            RuntimeError,
            "generator raised StopIteration",
            raised_at=pc,
        )
    if payload is not None:
        return payload
    if isinstance(current_exception, BaseException):
        return SymbolicException.concrete(
            type(current_exception),
            str(current_exception),
            raised_at=pc,
        )
    if current_exception is not None:
        return current_exception
    return SymbolicException.concrete(
        RuntimeError,
        "generator raised StopIteration",
        raised_at=pc,
    )


def _symbolic_exception_payload(value: object) -> SymbolicException | None:
    """Extract a symbolic exception payload from a direct or modeled stack value."""
    if isinstance(value, SymbolicException):
        return value
    modeled_value = getattr(value, "_modeled_object", None)
    return modeled_value if isinstance(modeled_value, SymbolicException) else None


def handle_common_call_intrinsic_2(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Dispatch ``CALL_INTRINSIC_2`` (Python 3.12+) by intrinsic id.

    CPython stack effect: pops two operands and pushes one result. Supports reraise
    passthrough (1), ``TypeVar`` bound/constrained placeholders (2–3), typed-function
    passthrough (4), and a symbolic fallback.

    Side Effects:
        Adds feasibility literals when synthesizing stack values; advances PC.

    Limitations:
        Does not execute real typing runtime or exception chaining for reraise.
    """
    _arg2 = state.pop() if state.stack else None
    arg1 = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            exc_val, constraint = SymbolicValue.symbolic(f"reraise_{state.pc}")
            state = state.push(exc_val)
            state = state.add_constraint(constraint)
    elif intrinsic_id in (2, 3):
        names = {2: "TypeVar_bound", 3: "TypeVar_constrained"}
        tv_val, constraint = SymbolicValue.symbolic(f"{names[intrinsic_id]}_{state.pc}")
        state = state.push(tv_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 4:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            func_val, constraint = SymbolicValue.symbolic(f"typed_func_{state.pc}")
            state = state.push(func_val)
            state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
