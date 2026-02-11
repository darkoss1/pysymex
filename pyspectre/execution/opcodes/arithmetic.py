"""Arithmetic and binary operation opcodes."""

from __future__ import annotations
import dis
from typing import TYPE_CHECKING
import z3
from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.core.solver import get_model, is_satisfiable
from pyspectre.core.types import SymbolicString, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


def check_division_by_zero(
    right: SymbolicValue,
    state: VMState,
    op_name: str,
    left: SymbolicValue,
) -> list[Issue]:
    """Check if division by zero is possible and return issues."""
    issues = []
    if getattr(left, "is_path", None) is not None:
        zero_check_shortcut = [
            *state.path_constraints,
            left.is_path,
        ]
        if is_satisfiable(zero_check_shortcut):
            return []
    zero_check = [
        *state.path_constraints,
        right.is_int,
        right.z3_int == 0,
    ]
    if is_satisfiable(zero_check):
        issues.append(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message=f"Possible division by zero: {left.name} {op_name} {right.name}",
                constraints=list(zero_check),
                model=get_model(zero_check),
                pc=state.pc,
            )
        )
    return issues


@opcode_handler("UNARY_POSITIVE")
def handle_unary_positive(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unary positive - essentially no-op."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_NEGATIVE")
def handle_unary_negative(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unary negation."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        state.push(-top)
    else:
        state.push(top)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_NOT")
def handle_unary_not(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Boolean NOT."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        result = top.logical_not()
    else:
        result = SymbolicValue(
            _name=f"(not {getattr(top, 'name', str(top))})",
            z3_int=z3.IntVal(0),
            is_int=z3.BoolVal(False),
            z3_bool=z3.Not(top.could_be_truthy()),
            is_bool=z3.BoolVal(True),
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_INVERT")
def handle_unary_invert(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise NOT."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        state.push(~top)
    else:
        state.push(top)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_ADD")
def handle_binary_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary addition."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left + right
    elif isinstance(left, SymbolicString) and isinstance(right, SymbolicString):
        result = left + right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}+{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SUBTRACT")
def handle_binary_subtract(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary subtraction."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left - right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}-{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_MULTIPLY")
def handle_binary_multiply(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary multiplication."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left * right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}*{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE")
def handle_binary_divide(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary division with zero check."""
    right = state.pop()
    left = state.pop()
    issues = []
    op_name = "/" if instr.opname == "BINARY_TRUE_DIVIDE" else "//"
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        issues = check_division_by_zero(right, state, op_name, left)
        state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
        if instr.opname == "BINARY_TRUE_DIVIDE":
            result = left / right
        else:
            result = left // right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}{op_name}{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_MODULO")
def handle_binary_modulo(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary modulo with zero check."""
    right = state.pop()
    left = state.pop()
    issues = []
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        issues = check_division_by_zero(right, state, "%", left)
        state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
        result = left % right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}%{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_POWER")
def handle_binary_power(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary exponentiation."""
    right = state.pop()
    left = state.pop()
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left**right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}**{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_LSHIFT", "BINARY_RSHIFT")
def handle_binary_shift(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary shift operations."""
    right = state.pop()
    left = state.pop()
    op = "<<" if instr.opname == "BINARY_LSHIFT" else ">>"
    result, _ = SymbolicValue.symbolic(
        f"{getattr(left, 'name', 'a')}{op}{getattr(right, 'name', 'b')}"
    )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_AND")
def handle_binary_and(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise/logical AND."""
    right = state.pop()
    left = state.pop()
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left & right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}&{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_OR")
def handle_binary_or(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Bitwise/logical OR."""
    right = state.pop()
    left = state.pop()
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left | right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}|{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_XOR")
def handle_binary_xor(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise XOR."""
    right = state.pop()
    left = state.pop()
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left ^ right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}^{getattr(right, 'name', 'b')}"
        )
    state.push(result)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_OP")
def handle_binary_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unified binary operation (Python 3.11+)."""
    right = state.pop()
    left = state.pop()
    op_code = instr.argrepr
    issues = []
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        if op_code in {"+", "+="}:
            result = left + right
        elif op_code in {"-", "-="}:
            result = left - right
        elif op_code in {"*", "*="}:
            result = left * right
        elif op_code in {"/", "/="}:
            issues = check_division_by_zero(right, state, "/", left)
            state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
            result = left / right
        elif op_code in {"//", "//="}:
            issues = check_division_by_zero(right, state, "//", left)
            state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
            result = left // right
        elif op_code in {"%", "%="}:
            issues = check_division_by_zero(right, state, "%", left)
            state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
            result = left % right
        elif op_code in {"**", "**="}:
            result = left**right
        elif op_code in {"&", "&="}:
            result = left & right
        elif op_code in {"|", "|="}:
            result = left | right
        elif op_code in {"^", "^="}:
            result = left ^ right
        elif op_code in {"<<", "<<=", ">>", ">>="}:
            result, _ = SymbolicValue.symbolic(f"{left.name}{op_code}{right.name}")
        else:
            result, _ = SymbolicValue.symbolic(f"{left.name}{op_code}{right.name}")
    elif (
        isinstance(left, SymbolicString)
        and isinstance(right, SymbolicString)
        and op_code in {"+", "+="}
    ):
        result = left + right
    else:
        result, _ = SymbolicValue.symbolic(f"binop_{state.pc}")
    state.push(result)
    state.pc += 1
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)
