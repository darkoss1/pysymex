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
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("COMPARE_OP")
def handle_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation."""
    right = state.pop()
    left = state.pop()
    op_name = instr.argval

    if op_name.startswith("bool(") and op_name.endswith(")"):
        op_name = op_name[5:-1]

    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)

    left_is_int = getattr(left, "is_int", Z3_FALSE)
    right_is_int = getattr(right, "is_int", Z3_FALSE)
    left_is_str = getattr(left, "is_str", Z3_TRUE if isinstance(left, SymbolicString) else Z3_FALSE)
    right_is_str = getattr(
        right, "is_str", Z3_TRUE if isinstance(right, SymbolicString) else Z3_FALSE
    )

    left_int = getattr(left, "z3_int", Z3_ZERO)
    right_int = getattr(right, "z3_int", Z3_ZERO)
    left_str = getattr(left, "z3_str", z3.StringVal(""))
    right_str = getattr(right, "z3_str", z3.StringVal(""))

    both_int = z3.And(left_is_int, right_is_int)
    both_str = z3.And(left_is_str, right_is_str)

    mixed = z3.Not(z3.Or(both_int, both_str))
    from pysymex.core.solver import is_satisfiable, get_model
    from pysymex.analysis.detectors import Issue, IssueKind

    res_states = []
    res_issues = []

    if op_name not in ("==", "!="):
        if is_satisfiable([*state.path_constraints, mixed]):
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

    if is_satisfiable([*state.path_constraints, z3.Not(mixed)]) or op_name in ("==", "!="):
        ok_state = state.fork()
        if op_name not in ("==", "!="):
            ok_state = ok_state.add_constraint(z3.Not(mixed))

        if op_name == "==":
            res_bool = z3.If(
                both_int, left_int == right_int, z3.If(both_str, left_str == right_str, Z3_FALSE)
            )
        elif op_name == "!=":
            res_bool = z3.If(
                both_int, left_int != right_int, z3.If(both_str, left_str != right_str, Z3_TRUE)
            )
        elif op_name == "<":
            res_bool = z3.If(both_int, left_int < right_int, left_str < right_str)
        elif op_name == "<=":
            res_bool = z3.If(both_int, left_int <= right_int, left_str <= right_str)
        elif op_name == ">":
            res_bool = z3.If(both_int, left_int > right_int, left_str > right_str)
        elif op_name == ">=":
            res_bool = z3.If(both_int, left_int >= right_int, left_str >= right_str)
        else:
            res_bool = z3.Bool(f"cmp_{state.pc}")

        result = SymbolicValue(
            _name=f"compare_{state.pc}",
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=res_bool,
            is_bool=Z3_TRUE,
        )
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
    left_is_none = isinstance(left, SymbolicNone)
    right_is_none = isinstance(right, SymbolicNone)
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
        from pysymex.core.types import SymbolicObject

        if isinstance(left, SymbolicObject) and isinstance(right, SymbolicObject):
            is_same = left.z3_addr == right.z3_addr
        elif isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
            is_same = z3.BoolVal(left is right)
        else:
            is_same = z3.BoolVal(left is right)
    result_bool = z3.Not(is_same) if invert else is_same
    result = SymbolicValue(
        _name=f"({'is not' if invert else 'is'}_{state.pc})",
        z3_int=z3.IntVal(0),
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
        from pysymex.core.types import SymbolicDict

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
