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

"""Membership semantics for ``CONTAINS_OP``."""

from __future__ import annotations

from collections.abc import ItemsView, KeysView, ValuesView
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.compare.exact import exact_concrete_equal
from pysymex._internal.execution.opcodes.common.compare.guards import require_compare_stack_depth
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    MEMBERSHIP_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
    flag_unsupported_membership,
)

if TYPE_CHECKING:
    import dis
    from collections.abc import Iterable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_contains_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Membership test (in / not in)."""
    require_compare_stack_depth(state, instr, 2, "CONTAINS_OP operands")
    right = state.pop()
    left = state.pop()
    invert = bool(instr.argval)
    if isinstance(right, SymbolicValue):
        from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

        contains_method = lookup_modeled_method(right, "__contains__")
        if contains_method is not None:
            from pysymex._internal.execution.calls.interprocedural.entry import (
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
                    flag_unsupported_membership(
                        state=state,
                        reason=MEMBERSHIP_CALL_UNAVAILABLE_REASON,
                    ),
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
    elif isinstance(right, SymbolicDict):
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
        if isinstance(payload, (list, tuple, set, frozenset, range)):
            values = list(cast("Iterable[object]", payload))
    elif isinstance(haystack, (KeysView, ValuesView, ItemsView)):
        values = list(cast("Iterable[object]", haystack))
    elif isinstance(haystack, (list, tuple, set, frozenset, range)):
        values = list(cast("Iterable[object]", haystack))

    if values is None:
        return None
    if not values:
        return Z3_FALSE
    clauses = _symbolic_membership_clauses(needle, values)
    if clauses:
        return z3.Or(*clauses)
    exact_membership = _exact_concrete_membership(needle, values)
    if exact_membership is not None:
        return Z3_TRUE if exact_membership else Z3_FALSE
    try:
        return Z3_TRUE if needle in values else Z3_FALSE
    except TypeError:
        return None


def _symbolic_membership_clauses(needle: object, values: list[object]) -> list[z3.BoolRef]:
    """Return symbolic equality clauses for retained container membership."""
    clauses: list[z3.BoolRef] = []
    for value in values:
        clause = _symbolic_equality_clause(needle, value)
        if clause is not None:
            clauses.append(clause)
    return clauses


def _symbolic_equality_clause(left: object, right: object) -> z3.BoolRef | None:
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        return z3.Or(
            z3.And(_int_like(left), _int_like(right), left.z3_int == right.z3_int),
            z3.And(left.is_str, right.is_str, left.z3_str == right.z3_str),
            z3.And(left.is_none, right.is_none),
        )
    if isinstance(left, SymbolicValue):
        return _symbolic_value_literal_equality(left, right)
    if isinstance(right, SymbolicValue):
        return _symbolic_value_literal_equality(right, left)
    if isinstance(left, SymbolicString) and isinstance(right, SymbolicString):
        return left.z3_str == right.z3_str
    if isinstance(left, SymbolicString) and isinstance(right, str):
        return left.z3_str == ConstraintValues.string(right)
    if isinstance(right, SymbolicString) and isinstance(left, str):
        return right.z3_str == ConstraintValues.string(left)
    return None


def _symbolic_value_literal_equality(value: SymbolicValue, literal: object) -> z3.BoolRef | None:
    if isinstance(literal, bool):
        return z3.And(_int_like(value), value.z3_int == int(literal))
    if isinstance(literal, int):
        return z3.And(_int_like(value), value.z3_int == literal)
    if isinstance(literal, str):
        return z3.And(value.is_str, value.z3_str == ConstraintValues.string(literal))
    if literal is None:
        return value.is_none
    if isinstance(literal, SymbolicString):
        return z3.And(value.is_str, value.z3_str == literal.z3_str)
    return None


def _int_like(value: SymbolicValue) -> z3.BoolRef:
    return z3.Or(value.is_int, value.is_bool)


def _exact_concrete_membership(needle: object, values: Iterable[object]) -> bool | None:
    """Return exact membership when retained symbolic payloads can be unwrapped."""
    saw_unknown = False
    for value in values:
        equal = exact_concrete_equal(needle, value)
        if equal is True:
            return True
        if equal is None:
            saw_unknown = True
    if saw_unknown:
        return None
    return False


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
