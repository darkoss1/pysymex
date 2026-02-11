"""Comparison opcodes."""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
import z3
from pyspectre.core.types import SymbolicNone, SymbolicString, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


@opcode_handler("COMPARE_OP")
def handle_compare_op(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Comparison operation."""
    right = state.pop()
    left = state.pop()
    op_name = instr.argval
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        if op_name == "==":
            result = left == right
        elif op_name == "!=":
            result = left != right
        elif op_name == "<":
            result = left < right
        elif op_name == "<=":
            result = left <= right
        elif op_name == ">":
            result = left > right
        elif op_name == ">=":
            result = left >= right
        else:
            result = SymbolicValue(
                _name=f"({left.name}{op_name}{right.name})",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.Bool(f"cmp_{state.pc}"),
                is_bool=z3.BoolVal(True),
            )
    elif isinstance(left, SymbolicString) and isinstance(right, SymbolicString):
        if op_name == "==":
            result = left == right
        elif op_name == "!=":
            eq = left == right
            result = SymbolicValue(
                _name=f"({left.name}!={right.name})",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.Not(eq.z3_bool),
                is_bool=z3.BoolVal(True),
            )
        else:
            result = SymbolicValue(
                _name=f"({left.name}{op_name}{right.name})",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=z3.Bool(f"strcmp_{state.pc}"),
                is_bool=z3.BoolVal(True),
            )
    else:
        result = SymbolicValue(
            _name=f"compare_{state.pc}",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Bool(f"cmp_{state.pc}"),
            is_bool=z3.BoolVal(True),
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


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
            is_same = z3.And(z3.Not(right.is_int), z3.Not(right.is_bool))
        elif right_is_none and isinstance(left, SymbolicValue):
            is_same = z3.And(z3.Not(left.is_int), z3.Not(left.is_bool))
        else:
            is_same = z3.BoolVal(False)
    else:
        if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
            eq = left == right
            is_same = eq.z3_bool
        else:
            is_same = z3.Bool(f"is_{state.pc}")
    result_bool = z3.Not(is_same) if invert else is_same
    result = SymbolicValue(
        _name=f"({'is not' if invert else 'is'}_{state.pc})",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=result_bool,
        is_bool=z3.BoolVal(True),
    )
    state.push(result)
    state.pc += 1
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
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)
