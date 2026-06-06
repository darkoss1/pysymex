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

"""COMPARE_OP, IS_OP, and CONTAINS_OP handlers shared across Python versions.

Lowers rich comparisons through :class:`~pysymex.execution.opcodes.common.lowering.ComparisonLowerer`,
forks feasible ``TypeError`` paths when handlers exist, and dispatches modeled
``__eq__``/ordering/``__contains__`` via interprocedural calls. Solver checks use
:func:`~pysymex.execution.opcodes.common.path_feasibility.path_is_sat`.
"""

from __future__ import annotations

from collections.abc import Iterable
import dis
from typing import TYPE_CHECKING, TypeVar, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.bytecode import resolve_compare_op_symbol
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_ONE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_string_val
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.state.types import VMStateError
from pysymex.core.state.types import ProtocolCallCandidate
from pysymex.core.types.containers.dict_views import SymbolicDictView
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.sequences import SymbolicTuple
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.exact_compare import (
    exact_list_comparison_condition,
)
from pysymex.execution.opcodes.common.lowering import ComparisonLowerer
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    COMPARISON_CALL_UNAVAILABLE_REASON,
    MEMBERSHIP_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_COMPARISON_PROTOCOL,
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
    unsupported_comparison_event,
    unsupported_membership_event,
)
from pysymex.execution.opcodes.common.path_feasibility import path_is_sat

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Raise when the stack lacks operands required by a comparison opcode."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def _symbolic_membership_condition(needle: object, haystack: object) -> z3.BoolRef | None:
    """Build a Z3 membership predicate for supported concrete or symbolic containers."""
    bytes_condition = _exact_bytes_membership_condition(needle, haystack)
    if bytes_condition is not None:
        return bytes_condition

    values: list[object] | None = None
    if isinstance(haystack, SymbolicList):
        values = haystack.concrete_items
    elif isinstance(haystack, SymbolicDict):
        return haystack.concrete_key_presence_condition(needle)
    elif isinstance(haystack, SymbolicDictView):
        if haystack.kind == "keys":
            presence = haystack.source.concrete_key_presence_condition(needle)
            if presence is not None:
                return presence
            if isinstance(needle, SymbolicString):
                return haystack.source.contains_key(needle).z3_bool
        values = haystack.concrete_items
    elif isinstance(haystack, SymbolicValue):
        payload = haystack.value
        if type(payload) is set:
            val_set = cast("set[object]", payload)
            values = list(val_set)
    elif isinstance(haystack, (list, tuple, set, frozenset, range)):
        values = list(cast("Iterable[object]", haystack))

    if values is None:
        return None
    if not values:
        return Z3_FALSE
    if isinstance(needle, SymbolicValue):
        clauses: list[z3.BoolRef] = []
        for value in values:
            if isinstance(value, SymbolicValue):
                value = value.value
            if isinstance(value, bool):
                clauses.append(needle.z3_int == int(value))
            elif isinstance(value, int):
                clauses.append(needle.z3_int == value)
            elif isinstance(value, str):
                clauses.append(needle.z3_str == get_string_val(value))
        if clauses:
            return z3.Or(*clauses)
    if isinstance(needle, SymbolicString):
        clauses = [
            needle.z3_str == get_string_val(value) for value in values if isinstance(value, str)
        ]
        if clauses:
            return z3.Or(*clauses)
    exact_membership = _exact_concrete_membership(needle, values)
    if exact_membership is not None:
        return Z3_TRUE if exact_membership else Z3_FALSE
    try:
        return Z3_TRUE if needle in values else Z3_FALSE
    except TypeError:
        return None


def _exact_concrete_membership(needle: object, values: Iterable[object]) -> bool | None:
    """Return exact membership when retained symbolic payloads can be unwrapped."""
    saw_unknown = False
    for value in values:
        equal = _exact_concrete_equal(needle, value)
        if equal is True:
            return True
        if equal is None:
            saw_unknown = True
    if saw_unknown:
        return None
    return False


def _exact_concrete_equal(left: object, right: object) -> bool | None:
    left_value = _exact_concrete_payload(left)
    right_value = _exact_concrete_payload(right)
    if left_value is _UNKNOWN_MEMBERSHIP_VALUE or right_value is _UNKNOWN_MEMBERSHIP_VALUE:
        return None
    if isinstance(left_value, tuple) and isinstance(right_value, tuple):
        left_tuple = cast("tuple[object, ...]", left_value)
        right_tuple = cast("tuple[object, ...]", right_value)
        if len(left_tuple) != len(right_tuple):
            return False
        saw_unknown = False
        for left_item, right_item in zip(left_tuple, right_tuple, strict=True):
            equal = _exact_concrete_equal(left_item, right_item)
            if equal is False:
                return False
            if equal is None:
                saw_unknown = True
        return None if saw_unknown else True
    return _exact_bool_or_none(left_value == right_value)


def _exact_bool_or_none(value: object) -> bool | None:
    """Return a concrete bool only when an equality result is fully decided."""
    if isinstance(value, bool):
        return value
    if isinstance(value, z3.BoolRef):
        simplified = z3.simplify(value)
        if z3.is_true(simplified):
            return True
        if z3.is_false(simplified):
            return False
    return None


def _exact_equality_condition(left: object, right: object, op_name: str) -> z3.BoolRef | None:
    if op_name not in {"==", "!="}:
        return None
    equal = _exact_concrete_equal(left, right)
    if equal is None:
        return None
    if op_name == "!=":
        equal = not equal
    return Z3_TRUE if equal else Z3_FALSE


def _exact_bool_identity_condition(left: object, right: object) -> z3.BoolRef | None:
    left_value = _exact_concrete_payload(left)
    right_value = _exact_concrete_payload(right)
    if left_value is _UNKNOWN_MEMBERSHIP_VALUE or right_value is _UNKNOWN_MEMBERSHIP_VALUE:
        return None
    if not isinstance(left_value, bool) and not isinstance(right_value, bool):
        return None
    return Z3_TRUE if left_value is right_value else Z3_FALSE


def _exact_concrete_payload(value: object) -> object:
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return value.value
        if z3.is_true(z3.simplify(value.is_none)):
            return None
        if z3.is_true(z3.simplify(value.is_str)) and z3.is_string_value(value.z3_str):
            try:
                return value.z3_str.as_string()
            except z3.Z3Exception:
                return _UNKNOWN_MEMBERSHIP_VALUE
        return _UNKNOWN_MEMBERSHIP_VALUE
    if isinstance(value, SymbolicInt):
        simplified = z3.simplify(value.z3_int)
        if z3.is_int_value(simplified):
            return simplified.as_long()
        return _UNKNOWN_MEMBERSHIP_VALUE
    if isinstance(value, SymbolicBool):
        simplified = z3.simplify(value.z3_bool)
        if z3.is_true(simplified):
            return True
        if z3.is_false(simplified):
            return False
        return _UNKNOWN_MEMBERSHIP_VALUE
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return _UNKNOWN_MEMBERSHIP_VALUE
    if isinstance(value, SymbolicBytes):
        return (
            value.concrete_value if value.concrete_value is not None else _UNKNOWN_MEMBERSHIP_VALUE
        )
    if isinstance(value, SymbolicTuple):
        return tuple(_exact_concrete_payload(item) for item in value.elements)
    if isinstance(value, tuple):
        items = cast("tuple[object, ...]", value)
        return tuple(_exact_concrete_payload(item) for item in items)
    return value


def _exact_bytes_membership_condition(needle: object, haystack: object) -> z3.BoolRef | None:
    is_bytes_like, haystack_value = _bytes_like_haystack_value(haystack)
    if not is_bytes_like:
        return None

    needle_kind, needle_value, _message = _bytes_membership_needle(needle)
    if haystack_value is None:
        return None
    if needle_kind == "bytes" and needle_value is not None:
        return Z3_TRUE if needle_value in haystack_value else Z3_FALSE
    if needle_kind == "int" and isinstance(needle_value, int):
        return Z3_TRUE if int(needle_value) in haystack_value else Z3_FALSE
    return None


def _bytes_membership_exception(needle: object, haystack: object) -> tuple[IssueKind, str] | None:
    is_bytes_like, _haystack_value = _bytes_like_haystack_value(haystack)
    if not is_bytes_like:
        return None
    needle_kind, _needle_value, message = _bytes_membership_needle(needle)
    if needle_kind == "value_error":
        return IssueKind.VALUE_ERROR, message
    if needle_kind == "type_error":
        return IssueKind.TYPE_ERROR, message
    return None


def _bytes_like_haystack_value(value: object) -> tuple[bool, bytes | None]:
    raw_value = value.value if isinstance(value, SymbolicValue) else value
    if isinstance(raw_value, (bytes, bytearray)):
        return True, bytes(raw_value)
    if isinstance(value, SymbolicBytes):
        return True, value.concrete_value
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) in {"bytes", "bytearray"}:
        concrete_items = value.concrete_items
        if concrete_items is None:
            return True, None
        byte_values = _exact_byte_values(concrete_items)
        if byte_values is not None:
            return True, byte_values
        return True, None
    return False, None


def _bytes_membership_needle(value: object) -> tuple[str, bytes | int | None, str]:
    raw_value = value.value if isinstance(value, SymbolicValue) else value
    if isinstance(raw_value, bool):
        return "int", int(raw_value), ""
    if isinstance(raw_value, int):
        if 0 <= raw_value <= 255:
            return "int", raw_value, ""
        return "value_error", None, "byte must be in range(0, 256)"
    if isinstance(raw_value, (bytes, bytearray)):
        return "bytes", bytes(raw_value), ""
    if isinstance(raw_value, memoryview):
        return "bytes", raw_value.tobytes(), ""
    if isinstance(value, SymbolicBytes):
        return "bytes", value.concrete_value, ""
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) in {"bytes", "bytearray"}:
        concrete_items = value.concrete_items
        if concrete_items is None:
            return "bytes", None, ""
        byte_values = _exact_byte_values(concrete_items)
        if byte_values is not None:
            return "bytes", byte_values, ""
        return "bytes", None, ""
    if isinstance(value, SymbolicValue) and value.value is None:
        return "unknown", None, ""
    type_name = "str" if isinstance(value, SymbolicString) else type(raw_value).__name__
    return "type_error", None, f"a bytes-like object is required, not '{type_name}'"


def _exact_byte_values(items: list[object]) -> bytes | None:
    byte_values: list[int] = []
    for item in items:
        if not isinstance(item, int) or not 0 <= item <= 255:
            return None
        byte_values.append(item)
    return bytes(byte_values)


def _membership_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    issue_kind: IssueKind,
    message: str,
) -> OpcodeResult:
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        return OpcodeResult.continue_with(state.set_pc(handler_pc))
    exception_name = "ValueError" if issue_kind == IssueKind.VALUE_ERROR else "TypeError"
    issue = Issue(
        kind=issue_kind,
        message=f"Possible {exception_name}: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


_T = TypeVar("_T")
_UNKNOWN_MEMBERSHIP_VALUE = object()
_RICH_COMPARISON_METHODS = {
    "<": ("__lt__", "__gt__"),
    "<=": ("__le__", "__ge__"),
    "==": ("__eq__", "__eq__"),
    "!=": ("__ne__", "__ne__"),
    ">": ("__gt__", "__lt__"),
    ">=": ("__ge__", "__le__"),
}


def _right_rich_comparison_precedes_direct(left: object, right: object) -> bool:
    """Return whether a proven strict subtype receives rich-comparison priority."""
    from pysymex.models.objects import SymbolicInstance

    left_instance = getattr(left, "_modeled_object", None)
    right_instance = getattr(right, "_modeled_object", None)
    if not isinstance(left_instance, SymbolicInstance) or not isinstance(
        right_instance, SymbolicInstance
    ):
        return False
    right_class = right_instance.cls
    return (
        right_class is not left_instance.cls
        and bool(getattr(right_class, "_pysymex_bases_complete", False))
        and right_class.is_subclass_of(left_instance.cls)
    )


def _dispatch_modeled_rich_comparison(
    state: VMState,
    ctx: OpcodeDispatcher,
    left: StackValue,
    right: StackValue,
    op_name: str,
) -> OpcodeResult | None:
    """Dispatch modeled rich comparison via interprocedural dunder calls."""
    method_names = _RICH_COMPARISON_METHODS.get(op_name)
    if method_names is None:
        return None
    from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

    candidates: list[ProtocolCallCandidate] = []
    ordered_candidates = [
        (left, method_names[0], right),
        (right, method_names[1], left),
    ]
    if _right_rich_comparison_precedes_direct(left, right):
        ordered_candidates.reverse()
    for owner, method_name, argument in ordered_candidates:
        if lookup_modeled_method(owner, method_name) is not None:
            candidates.append(
                ProtocolCallCandidate(
                    owner=owner,
                    method_name=method_name,
                    argument=argument,
                )
            )
    if not candidates:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    first = candidates[0]
    method = lookup_modeled_method(first.owner, first.method_name)
    if method is not None:
        protocol_method = {"==": "__richcmp_eq__", "!=": "__richcmp_ne__"}.get(
            op_name, "__richcmp__"
        )
        result = perform_interprocedural_call_impl(
            state,
            ctx,
            method,
            [first.owner, first.argument],
            {},
            protocol_method=protocol_method,
            protocol_retained_operand=(left, right) if op_name in {"==", "!="} else None,
            protocol_fallbacks=tuple(candidates[1:]),
        )
        if result is not None:
            return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_COMPARISON_PROTOCOL],
        fallback_events=[
            unsupported_comparison_event(
                state=state,
                reason=COMPARISON_CALL_UNAVAILABLE_REASON,
            )
        ],
        terminal=True,
    )


def handle_common_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation with symbolic TypeError branching."""
    _require_stack_depth(state, instr, 2, "COMPARE_OP operands")

    right = state.pop()
    left = state.pop()
    op_name = resolve_compare_op_symbol(instr)
    exact_list_condition = exact_list_comparison_condition(left, right, op_name, state)
    if exact_list_condition is not None:
        result = SymbolicValue(
            _name=f"compare_{state.pc}",
            z3_int=z3.If(exact_list_condition, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=exact_list_condition,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    exact_equality_condition = _exact_equality_condition(left, right, op_name)
    if exact_equality_condition is not None:
        result = SymbolicValue(
            _name=f"compare_{state.pc}",
            z3_int=z3.If(exact_equality_condition, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=exact_equality_condition,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    modeled_result = _dispatch_modeled_rich_comparison(state, ctx, left, right, op_name)
    if modeled_result is not None:
        return modeled_result

    lowerer = ComparisonLowerer(state.pc)
    result, type_error_cond = lowerer.lower(left, right, op_name)

    if z3.is_false(type_error_cond):
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    # Check if a TypeError is possible (e.g. comparing string < int)
    path_constraints = state.path_constraints.to_list()
    if path_is_sat([*path_constraints, type_error_cond]):
        handler_pc = ctx.find_exception_handler(instr.offset)
        not_error = z3.Not(type_error_cond)
        if path_is_sat([*path_constraints, not_error]):
            success_state = state.fork().add_constraint(not_error)
            success_state = success_state.push(result)
            success_state = success_state.advance_pc()
            if handler_pc is None:
                return OpcodeResult.continue_with(success_state)

            error_state = state.fork().add_constraint(type_error_cond).set_pc(handler_pc)
            return OpcodeResult.branch([success_state, error_state])

        if handler_pc is None:
            return OpcodeResult.terminate()

        error_state = state.fork().add_constraint(type_error_cond).set_pc(handler_pc)
        return OpcodeResult.continue_with(error_state)

    # Standard path: No TypeError possible
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_is_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Identity comparison (is / is not)."""
    _require_stack_depth(state, instr, 2, "IS_OP operands")
    right = state.pop()
    left = state.pop()
    invert = bool(instr.argval)
    left_is_none = isinstance(left, SymbolicNone) or (
        isinstance(left, SymbolicValue) and z3.is_true(left.is_none)
    )
    right_is_none = isinstance(right, SymbolicNone) or (
        isinstance(right, SymbolicValue) and z3.is_true(right.is_none)
    )

    if left_is_none or right_is_none:
        if left_is_none and right_is_none:
            is_same = Z3_TRUE
        elif left_is_none and isinstance(right, SymbolicValue):
            is_same = right.is_none
        elif right_is_none and isinstance(left, SymbolicValue):
            is_same = left.is_none
        else:
            is_same = Z3_FALSE
    else:
        exact_bool_identity = _exact_bool_identity_condition(left, right)
        if exact_bool_identity is not None:
            is_same = exact_bool_identity
        elif isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
            is_same = left.z3_addr == right.z3_addr
        elif isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
            is_same = z3.And(
                z3.Implies(z3.And(left.is_obj, right.is_obj), left.z3_addr == right.z3_addr),
                z3.Implies(z3.And(left.is_int, right.is_int), left.z3_int == right.z3_int),
                z3.Implies(z3.And(left.is_str, right.is_str), left.z3_str == right.z3_str),
                left.is_int == right.is_int,
                left.is_obj == right.is_obj,
                left.is_str == right.is_str,
            )
        else:
            is_same = Z3_TRUE if left is right else Z3_FALSE

    result_bool = z3.Not(is_same) if invert else is_same
    result = SymbolicValue(
        _name=f"({'is not' if invert else 'is'}_{state.pc})",
        z3_int=z3.If(result_bool, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=result_bool,
        is_bool=Z3_TRUE,
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_contains_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Membership test (in / not in)."""
    _require_stack_depth(state, instr, 2, "CONTAINS_OP operands")
    right = state.pop()
    left = state.pop()
    invert = bool(instr.argval)
    if isinstance(right, SymbolicValue):
        from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

        contains_method = lookup_modeled_method(right, "__contains__")
        if contains_method is not None:
            from pysymex.execution.calls.interprocedural import (
                perform_interprocedural_call_impl,
            )

            result = perform_interprocedural_call_impl(
                state,
                ctx,
                contains_method,
                [right, left],
                {},
                protocol_method="__contains_not__" if invert else "__contains__",
            )
            if result is not None:
                return result
            return OpcodeResult(
                new_states=[],
                issues=[],
                degraded_passes=[UNSUPPORTED_MEMBERSHIP_PROTOCOL],
                fallback_events=[
                    unsupported_membership_event(
                        state=state,
                        reason=MEMBERSHIP_CALL_UNAVAILABLE_REASON,
                    )
                ],
                terminal=True,
            )
    if isinstance(right, SymbolicObject) and right.address != -1:
        mem_obj = state.memory.get(right.address)
        if mem_obj is not None:
            right = mem_obj
    if isinstance(left, SymbolicObject) and left.address != -1:
        mem_obj = state.memory.get(left.address)
        if mem_obj is not None:
            left = mem_obj
    bytes_membership_exception = _bytes_membership_exception(left, right)
    if bytes_membership_exception is not None:
        return _membership_exception_result(instr, state, ctx, *bytes_membership_exception)
    if isinstance(right, SymbolicString) and isinstance(left, SymbolicString):
        contains_result = right.contains(left)
        result_bool = contains_result.z3_bool
    else:
        if isinstance(right, SymbolicDict):
            concrete_presence = right.concrete_key_presence_condition(left)
            if concrete_presence is not None:
                result_bool = concrete_presence
            elif isinstance(left, SymbolicString):
                contains_result = right.contains_key(left)
                result_bool = contains_result.z3_bool
            else:
                result_bool = _symbolic_membership_condition(left, right)
                if result_bool is None:
                    result_bool = z3.Bool(f"contains_{state.pc}")
        else:
            result_bool = _symbolic_membership_condition(left, right)
            if result_bool is None:
                result_bool = z3.Bool(f"contains_{state.pc}")
    if invert:
        result_bool = z3.Not(result_bool)
    result = SymbolicValue(
        _name=f"({'not in' if invert else 'in'}_{state.pc})",
        z3_int=z3.If(result_bool, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=result_bool,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
