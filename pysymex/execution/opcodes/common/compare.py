# pysymex: Python Symbolic Execution & Formal Verification
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

"""Common comparison operations for opcodes."""

from __future__ import annotations

from collections.abc import Iterable
import dis
from typing import TYPE_CHECKING, TypeVar, cast

import z3

from pysymex.core.solver.constraints import quick_contradiction_check
from pysymex.core.solver.engine import is_satisfiable
from pysymex.core.types.scalars import (
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.core.state import VMStateError
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.opcodes.common.lowering import ComparisonLowerer

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Check path satisfiability with a cheap fallback on deep paths."""
    if len(constraints) < 12:
        return is_satisfiable(constraints)
    return not quick_contradiction_check(constraints)


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def _symbolic_membership_condition(needle: object, haystack: object) -> z3.BoolRef | None:
    values: list[object] | None = None
    if isinstance(haystack, SymbolicList):
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
        return z3.BoolVal(False)
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
                clauses.append(needle.z3_str == z3.StringVal(value))
        if clauses:
            return z3.Or(*clauses)
    if isinstance(needle, SymbolicString):
        clauses = [
            needle.z3_str == z3.StringVal(value) for value in values if isinstance(value, str)
        ]
        if clauses:
            return z3.Or(*clauses)
    try:
        return z3.BoolVal(needle in values)
    except TypeError:
        return None


_T = TypeVar("_T")


def handle_common_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation with symbolic TypeError branching."""
    _require_stack_depth(state, instr, 2, "COMPARE_OP operands")

    right = state.pop()
    left = state.pop()
    raw_op_name = instr.argval
    op_name = raw_op_name if isinstance(raw_op_name, str) else str(raw_op_name)

    lowerer = ComparisonLowerer(state.pc)
    result, type_error_cond = lowerer.lower(left, right, op_name)

    # Check if a TypeError is possible (e.g. comparing string < int)
    path_constraints = state.path_constraints.to_list()
    if _path_is_sat([*path_constraints, type_error_cond]):
        handler_pc = ctx.find_exception_handler(instr.offset)
        not_error = z3.Not(type_error_cond)
        if _path_is_sat([*path_constraints, not_error]):
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
            is_same = z3.BoolVal(True)
        elif left_is_none and isinstance(right, SymbolicValue):
            is_same = right.is_none
        elif right_is_none and isinstance(left, SymbolicValue):
            is_same = left.is_none
        else:
            is_same = z3.BoolVal(False)
    else:
        if isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
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
            is_same = z3.BoolVal(left is right)

    result_bool = z3.Not(is_same) if invert else is_same
    result = SymbolicValue(
        _name=f"({'is not' if invert else 'is'}_{state.pc})",
        z3_int=z3.If(result_bool, z3.IntVal(1), z3.IntVal(0)),
        is_int=z3.BoolVal(False),
        z3_bool=result_bool,
        is_bool=z3.BoolVal(True),
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
    if isinstance(right, SymbolicObject) and right.address != -1:
        mem_obj = state.memory.get(right.address)
        if mem_obj is not None:
            right = mem_obj
    if isinstance(right, SymbolicString) and isinstance(left, SymbolicString):
        contains_result = right.contains(left)
        result_bool = contains_result.z3_bool
    else:
        if isinstance(right, SymbolicDict) and isinstance(left, SymbolicString):
            contains_result = right.contains_key(left)
            result_bool = contains_result.z3_bool
        else:
            result_bool = _symbolic_membership_condition(left, right)
            if result_bool is None:
                result_bool = z3.Bool(f"contains_{state.pc}")
    if invert:
        result_bool = z3.Not(result_bool)
    result = SymbolicValue(
        _name=f"({'not in' if invert else 'in'}_{state.pc})",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=result_bool,
        is_bool=z3.BoolVal(True),
    )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
