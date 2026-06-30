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

"""``CALL_INTRINSIC_*`` dispatch and list-to-tuple intrinsic lowering."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import concrete_exception
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.generic_aliases import modeled_runtime_generic_alias
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.control.fallbacks import (
    LIST_TO_TUPLE_TYPE_UNCERTAIN,
    list_to_tuple_type_uncertain_event,
)
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.dispatch import (
    continue_numeric_unary_positive_value,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

_UNKNOWN_PREP_RERAISE_STAR = object()


def handle_list_to_tuple_intrinsic(
    instr: dis.Instruction,
    state: VMState,
    arg: object,
) -> OpcodeResult:
    """Lower ``INTRINSIC_LIST_TO_TUPLE`` via concrete, modeled, or havoc tuple paths.

    CPython stack effect: consumes the list/tuple carrier and pushes a tuple. Concrete
    sequences use :class:`~pysymex._internal.execution.opcodes.common.lowering.CollectionLowerer`
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
    concrete_sequence = ConcreteExtractionPolicy.sequence(payload)
    if concrete_sequence is not None:
        items = [StackValuePolicy.coerce(item) for item in concrete_sequence]
        lowerer = CollectionLowerer(state.pc)
        lowered = lowerer.build_tuple(items)
        state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
        state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
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


def handle_common_call_intrinsic_1(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Dispatch ``CALL_INTRINSIC_1`` (Python 3.12+) by intrinsic id.

    CPython stack effect: pops one operand (when present) and pushes the intrinsic
    result. Handles ``None``/``Ellipsis`` pushes, generator ``StopIteration`` wrapper,
    unary-positive forwarding (intrinsic 5), list-to-tuple (6), typing placeholders
    (7-11), and a symbolic fallback for unknown ids.

    Side Effects:
        May delegate to :func:`continue_numeric_unary_positive_value` or
        :func:`handle_common_list_to_tuple_intrinsic`; otherwise adds feasibility
        literals for introduced symbols.

    Limitations:
        Typing and generic-alias intrinsics are symbolic stubs, not full ``typing``
        semantics.
    """
    arg = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id in (1, 2):
        state = state.push(SymbolicNoneType())
    elif intrinsic_id == 3:
        state = state.push(_stopiteration_error_value(state, state.pc))
    elif intrinsic_id == 4:
        wrapped, constraint = SymbolicValue.symbolic(f"async_gen_wrap_{state.pc}")
        state = state.push(wrapped)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 5:
        return continue_numeric_unary_positive_value(instr, state, ctx, arg)
    elif intrinsic_id == 6:
        return handle_list_to_tuple_intrinsic(instr, state, arg)
    elif intrinsic_id in (7, 8, 9):
        type_names = {7: "TypeVar", 8: "ParamSpec", 9: "TypeVarTuple"}
        type_val, constraint = SymbolicValue.symbolic(f"{type_names[intrinsic_id]}_{state.pc}")
        state = state.push(type_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 10:
        alias = modeled_runtime_generic_alias(arg, (), state.pc)
        if alias is not None:
            state = state.push(alias)
        else:
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


def handle_control_call_intrinsic_2(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Dispatch ``CALL_INTRINSIC_2`` (Python 3.12+) by intrinsic id.

    CPython stack effect: pops two operands and pushes one result. Supports reraise
    passthrough (1), ``TypeVar`` bound/constrained placeholders (2-3), typed-function
    passthrough (4), and a symbolic fallback.

    Side Effects:
        Adds feasibility literals when synthesizing stack values; advances PC.

    Limitations:
        Does not execute real typing runtime or exception chaining for reraise.
    """
    arg2 = state.pop() if state.stack else None
    arg1 = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        reraise_value = prep_reraise_star_result(state, arg1, arg2)
        if reraise_value is not None:
            state = state.push(cast("StackValue", reraise_value))
        elif arg1 is not None:
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


def prep_reraise_star_result(
    state: VMState,
    original: object,
    reraised: object,
) -> object | None:
    """Return a concrete ``PREP_RERAISE_STAR`` result for retained reraised lists."""
    payload = _resolve_list_to_tuple_payload(state, reraised)
    original_group = _symbolic_exception_payload(original)
    result: object
    if isinstance(payload, SymbolicList) and payload.concrete_items is not None:
        result = _reraise_star_members_result(payload.concrete_items, original_group)
    elif isinstance(payload, list):
        result = _reraise_star_members_result(cast("list[object]", payload), original_group)
    elif isinstance(payload, tuple):
        result = _reraise_star_members_result(cast("tuple[object, ...]", payload), original_group)
    else:
        result = _UNKNOWN_PREP_RERAISE_STAR
    if result is _UNKNOWN_PREP_RERAISE_STAR:
        return None
    return result


def _reraise_star_members_result(
    members: list[object] | tuple[object, ...],
    original_group: SymbolicException | None,
) -> object:
    """Return CPython's result for retained ``PREP_RERAISE_STAR`` members."""
    retained = [member for member in members if not _is_none_reraise_member(member)]
    if not retained:
        return SymbolicNoneType()
    if len(retained) == 1:
        return retained[0]
    if original_group is not None and _is_exception_group_payload(original_group):
        return _retained_exception_group(original_group, retained)
    return _UNKNOWN_PREP_RERAISE_STAR


def _is_exception_group_payload(payload: SymbolicException | None) -> bool:
    """Return whether *payload* models a concrete exception group."""
    return (
        payload is not None
        and isinstance(payload.exc_type, type)
        and issubclass(payload.exc_type, BaseExceptionGroup)
    )


def _retained_exception_group(
    original_group: SymbolicException,
    retained: list[object],
) -> SymbolicException:
    """Return the group-shaped remainder CPython keeps for ``except*`` cleanup."""
    message = original_group.args[0] if original_group.args else original_group.message or ""
    exc_type = original_group.exc_type
    if not isinstance(exc_type, type) or not issubclass(exc_type, BaseExceptionGroup):
        exc_type = ExceptionGroup
    return concrete_exception(
        cast("type[BaseException]", exc_type),
        message,
        retained,
        raised_at=original_group.raised_at,
        line_number=original_group.line_number,
    )


def _is_none_reraise_member(member: object) -> bool:
    """Return true for none markers appended by ``except*`` remainder paths."""
    if member is None or isinstance(member, SymbolicNoneType):
        return True
    if isinstance(member, SymbolicValue):
        return member.value is None or member.affinity_type == "none"
    return False


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
        return concrete_exception(
            RuntimeError,
            "generator raised StopIteration",
            raised_at=pc,
        )
    if payload is not None:
        return payload
    if isinstance(current_exception, BaseException):
        return concrete_exception(
            type(current_exception),
            str(current_exception),
            raised_at=pc,
        )
    if current_exception is not None:
        return current_exception
    return concrete_exception(
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
