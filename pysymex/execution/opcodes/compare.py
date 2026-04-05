# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Comparison opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.types import (
    Z3_FALSE,
    Z3_TRUE,
    Z3_ZERO,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.core.types_containers import SymbolicDict, SymbolicObject
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _if_bool(condition: z3.BoolRef, when_true: z3.BoolRef, when_false: z3.BoolRef) -> z3.BoolRef:
    """Typed bool-only wrapper around z3.If."""
    return z3.If(condition, when_true, when_false)


def _get_bool_attr(obj: object, name: str, default: z3.BoolRef) -> z3.BoolRef:
    value = getattr(obj, name, default)
    return value if isinstance(value, z3.BoolRef) else default


def _get_arith_attr(obj: object, name: str, default: z3.ArithRef) -> z3.ArithRef:
    value = getattr(obj, name, default)
    return value if isinstance(value, z3.ArithRef) else default


def _get_fp_attr(obj: object, name: str, default: z3.FPRef) -> z3.FPRef:
    value = getattr(obj, name, default)
    return value if isinstance(value, z3.FPRef) else default


def _get_seq_attr(obj: object, name: str, default: z3.SeqRef) -> z3.SeqRef:
    value = getattr(obj, name, default)
    return value if isinstance(value, z3.SeqRef) else default


def _compare_strings(op_name: str, left: z3.SeqRef, right: z3.SeqRef) -> z3.BoolRef:
    if op_name == "==":
        return left == right
    if op_name == "!=":
        return left != right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return Z3_FALSE


@opcode_handler("COMPARE_OP")
def handle_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation."""
    right = state.pop()
    left = state.pop()
    raw_op_name = instr.argval
    op_name = raw_op_name if isinstance(raw_op_name, str) else str(raw_op_name)

    if op_name.startswith("bool(") and op_name.endswith(")"):
        op_name = op_name[5:-1]

    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)

    left_is_int = _get_bool_attr(left, "is_int", Z3_FALSE)
    right_is_int = _get_bool_attr(right, "is_int", Z3_FALSE)
    left_is_float = _get_bool_attr(left, "is_float", Z3_FALSE)
    right_is_float = _get_bool_attr(right, "is_float", Z3_FALSE)
    left_is_bool = _get_bool_attr(left, "is_bool", Z3_FALSE)
    right_is_bool = _get_bool_attr(right, "is_bool", Z3_FALSE)

    left_is_str = _get_bool_attr(
        left,
        "is_str",
        Z3_TRUE if isinstance(left, SymbolicString) else Z3_FALSE,
    )
    right_is_str = _get_bool_attr(
        right,
        "is_str",
        Z3_TRUE if isinstance(right, SymbolicString) else Z3_FALSE,
    )

    left_int = _get_arith_attr(left, "z3_int", Z3_ZERO)
    right_int = _get_arith_attr(right, "z3_int", Z3_ZERO)
    left_float = _get_fp_attr(left, "z3_float", z3.FPVal(0.0, z3.Float64()))
    right_float = _get_fp_attr(right, "z3_float", z3.FPVal(0.0, z3.Float64()))
    left_str = _get_seq_attr(left, "z3_str", z3.StringVal(""))
    right_str = _get_seq_attr(right, "z3_str", z3.StringVal(""))

    left_num = z3.Or(left_is_int, left_is_float, left_is_bool)
    right_num = z3.Or(right_is_int, right_is_float, right_is_bool)

    both_numeric = z3.And(left_num, right_num)
    both_str = z3.And(left_is_str, right_is_str)

    mixed = z3.Not(z3.Or(both_numeric, both_str))
    from pysymex.analysis.detectors import Issue, IssueKind
    from pysymex.core.solver import get_model, is_satisfiable

    res_states = []
    res_issues = []

    path_constraints = state.path_constraints.to_list()

    if op_name not in ("==", "!="):
        if is_satisfiable([*path_constraints, mixed]):
            if not is_satisfiable([*path_constraints, z3.Not(mixed)]):
                err_state = state.fork()
                err_state = err_state.add_constraint(mixed)
                res_issues.append(
                    Issue(
                        IssueKind.TYPE_ERROR,
                        f"TypeError: '{op_name}' not supported between mixed types",
                        constraints=list(err_state.path_constraints),
                        model=get_model(list(err_state.path_constraints)),
                        pc=state.pc,
                    )
                )

    if is_satisfiable([*path_constraints, z3.Not(mixed)]) or op_name in ("==", "!="):
        ok_state = state.fork()
        if op_name not in ("==", "!="):
            ok_state = ok_state.add_constraint(z3.Not(mixed))

        def cmp_num(
            op: str,
            l_int: z3.ArithRef,
            l_float: z3.FPRef,
            r_int: z3.ArithRef,
            r_float: z3.FPRef,
            l_is_int: z3.BoolRef,
            r_is_int: z3.BoolRef,
        ) -> z3.BoolRef:
            rm = z3.RoundNearestTiesToEven()
            sort = z3.Float64()

            l_val_fp = z3.If(l_is_int, z3.fpToFP(rm, z3.ToReal(l_int), sort), l_float)
            r_val_fp = z3.If(r_is_int, z3.fpToFP(rm, z3.ToReal(r_int), sort), r_float)

            if op == "==":
                fp_cmp = z3.fpEQ(l_val_fp, r_val_fp)
                int_cmp = l_int == r_int
            elif op == "!=":
                fp_cmp = z3.Not(z3.fpEQ(l_val_fp, r_val_fp))
                int_cmp = l_int != r_int
            elif op == "<":
                fp_cmp = z3.fpLT(l_val_fp, r_val_fp)
                int_cmp = l_int < r_int
            elif op == "<=":
                fp_cmp = z3.fpLEQ(l_val_fp, r_val_fp)
                int_cmp = l_int <= r_int
            elif op == ">":
                fp_cmp = z3.fpGT(l_val_fp, r_val_fp)
                int_cmp = l_int > r_int
            elif op == ">=":
                fp_cmp = z3.fpGEQ(l_val_fp, r_val_fp)
                int_cmp = l_int >= r_int
            else:
                return Z3_FALSE

            return _if_bool(z3.And(l_is_int, r_is_int), int_cmp, fp_cmp)

        l_int_like = z3.Or(left_is_int, left_is_bool)
        r_int_like = z3.Or(right_is_int, right_is_bool)

        if op_name in ("==", "!=", "<", "<=", ">", ">="):
            string_cmp = _compare_strings(op_name, left_str, right_str)
            mixed_cmp = (
                Z3_FALSE
                if op_name == "=="
                else Z3_TRUE
                if op_name == "!="
                else z3.Bool(f"cmp_mixed_{state.pc}")
            )
            res_bool = _if_bool(
                both_numeric,
                cmp_num(
                    op_name, left_int, left_float, right_int, right_float, l_int_like, r_int_like
                ),
                _if_bool(
                    both_str,
                    string_cmp,
                    mixed_cmp,
                ),
            )
        else:
            res_bool = z3.Bool(f"cmp_{state.pc}")

        result = SymbolicValue(
            _name=f"compare_{state.pc}",
            z3_int=z3.If(res_bool, z3.IntVal(1), Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=res_bool,
            is_bool=Z3_TRUE,
        )
        result.affinity_type = "bool"
        ok_state = ok_state.push(result)
        ok_state = ok_state.advance_pc()
        res_states.append(ok_state)

    if not res_states:
        return OpcodeResult(new_states=[], issues=res_issues, terminal=True)
    return OpcodeResult.branch(res_states, issues=res_issues)


@opcode_handler("IS_OP")
def handle_is_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Identity comparison (is / is not)."""
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


@opcode_handler("CONTAINS_OP")
def handle_contains_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Membership test (in / not in)."""
    right = state.pop()
    left = state.pop()
    invert = bool(instr.argval)
    if isinstance(right, SymbolicString) and isinstance(left, SymbolicString):
        contains_result = right.contains(left)
        result_bool = contains_result.z3_bool
    else:
        if isinstance(right, SymbolicDict) and isinstance(left, SymbolicString):
            contains_result = right.contains_key(left)
            result_bool = contains_result.z3_bool
        else:
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
