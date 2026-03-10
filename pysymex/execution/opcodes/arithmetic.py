"""Arithmetic and binary operation opcodes."""

from __future__ import annotations

import dis
import logging
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.solver import get_model, is_satisfiable
from pysymex.core.type_checks import is_overloaded_arithmetic
from pysymex.core.types import (
    Z3_FALSE,
    SymbolicString,
    SymbolicValue,
    bv_to_int,
    int_to_bv,
    merge_taint,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.execution.opcodes.control import get_truthy_expr

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher

logger = logging.getLogger(__name__)


def check_division_by_zero(
    right: SymbolicValue,
    state: VMState,
    op_name: str,
    left: SymbolicValue,
) -> list[Issue]:
    """Check if division by zero is possible and return issues."""
    issues: list[Issue] = []

    if is_overloaded_arithmetic(left, right):
        return []

    if z3.is_int_value(right.z3_int) and right.z3_int.as_long() == 0:
        issues.append(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message=f"Division by zero: {left.name} {op_name} {right.name}",
                constraints=[],
                model={},
                pc=state.pc,
            )
        )
        return issues

    zero_check = [
        *state.path_constraints,
        right.is_int,
        right.z3_int == 0,
    ]
    if is_satisfiable(zero_check):
        logger.debug("Division by zero SAT for %s at PC %d", right.name, state.pc)
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


def check_negative_shift(
    right: SymbolicValue,
    state: VMState,
    op_name: str,
    left: SymbolicValue,
) -> list[Issue]:
    """Check if a negative shift count is possible and return issues."""
    issues: list[Issue] = []

    if z3.is_int_value(right.z3_int):
        if right.z3_int.as_long() < 0:
            issues.append(
                Issue(
                    kind=IssueKind.VALUE_ERROR,
                    message=f"Definite negative shift count: {left.name} {op_name} {right.name}",
                    constraints=[],
                    model={},
                    pc=state.pc,
                )
            )
        return issues

    neg_check = [*state.path_constraints, right.is_int, right.z3_int < 0]
    if is_satisfiable(neg_check):
        issues.append(
            Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Possible negative shift count: {left.name} {op_name} {right.name}",
                constraints=list(neg_check),
                model=get_model(neg_check),
                pc=state.pc,
            )
        )
    return issues


def _is_concrete_zero_divisor(value: SymbolicValue) -> bool:
    return z3.is_int_value(value.z3_int) and value.z3_int.as_long() == 0


@opcode_handler("UNARY_POSITIVE")
def handle_unary_positive(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unary positive — pop TOS, push +TOS (identity for numeric types).

    BUG-009 fix: the previous implementation advanced PC without touching
    the stack, leaving TOS in place instead of popping and re-pushing it.
    For numeric types +x == x, so we simply pop and push back unchanged.
    """
    top = state.pop()
    state = state.push(top)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_NEGATIVE")
def handle_unary_negative(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unary negation."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        state = state.push(-top)
    else:
        state = state.push(-top if isinstance(top, (int, float)) else top)
    state = state.advance_pc()
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
            z3_bool=z3.Not(get_truthy_expr(top)),
            is_bool=z3.BoolVal(True),
        )
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_INVERT")
def handle_unary_invert(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise NOT."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        state = state.push(~top)
    else:
        state = state.push(~top if isinstance(top, int) else top)
    state = state.advance_pc()
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
    issues: list[Issue] = []
    if (isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue)) or (
        isinstance(left, SymbolicString) and isinstance(right, SymbolicString)
    ):
        result = left + right
    else:
        type_error_cond = [
            *state.path_constraints,
            z3.Not(z3.And(getattr(left, "is_int", Z3_FALSE), getattr(right, "is_int", Z3_FALSE))),
            z3.Not(
                z3.And(
                    getattr(left, "is_str", Z3_FALSE) if hasattr(left, "is_str") else Z3_FALSE,
                    getattr(right, "is_str", Z3_FALSE) if hasattr(right, "is_str") else Z3_FALSE,
                )
            ),
        ]
        if is_satisfiable(type_error_cond):
            issues.append(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {getattr(left, 'name', 'a')} + {getattr(right, 'name', 'b')}",
                    constraints=list(type_error_cond),
                    model=get_model(type_error_cond),
                    pc=state.pc,
                )
            )

        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}+{getattr(right, 'name', 'b')}"
        )

    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
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
    issues: list[Issue] = []
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left - right
    else:
        type_error_cond = [
            *state.path_constraints,
            z3.Not(z3.And(getattr(left, "is_int", Z3_FALSE), getattr(right, "is_int", Z3_FALSE))),
        ]
        if is_satisfiable(type_error_cond):
            issues.append(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {getattr(left, 'name', 'a')} - {getattr(right, 'name', 'b')}",
                    constraints=list(type_error_cond),
                    model=get_model(type_error_cond),
                    pc=state.pc,
                )
            )
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}-{getattr(right, 'name', 'b')}"
        )
    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
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
    issues: list[Issue] = []
    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        result = left * right
    else:
        type_error_cond = [
            *state.path_constraints,
            z3.Not(z3.And(getattr(left, "is_int", Z3_FALSE), getattr(right, "is_int", Z3_FALSE))),
        ]
        if is_satisfiable(type_error_cond):
            issues.append(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {getattr(left, 'name', 'a')} * {getattr(right, 'name', 'b')}",
                    constraints=list(type_error_cond),
                    model=get_model(type_error_cond),
                    pc=state.pc,
                )
            )
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}*{getattr(right, 'name', 'b')}"
        )
    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
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
        if any(i.kind == IssueKind.DIVISION_BY_ZERO and not i.constraints for i in issues):
            return OpcodeResult(new_states=[], issues=issues, terminal=True)

        state = state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
        result = left / right if instr.opname == "BINARY_TRUE_DIVIDE" else left // right
    else:
        type_error_cond = [
            *state.path_constraints,
            z3.Not(z3.And(getattr(left, "is_int", Z3_FALSE), getattr(right, "is_int", Z3_FALSE))),
        ]
        if is_satisfiable(type_error_cond):
            issues.append(
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Possible TypeError: {getattr(left, 'name', 'a')} {op_name} {getattr(right, 'name', 'b')}",
                    constraints=list(type_error_cond),
                    model=get_model(type_error_cond),
                    pc=state.pc,
                )
            )
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}{op_name}{getattr(right, 'name', 'b')}"
        )
    state = state.push(result)
    state = state.advance_pc()
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
        if _is_concrete_zero_divisor(right):
            return OpcodeResult(new_states=[], issues=issues, terminal=True)
        state = state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
        result = left % right
    else:
        result, _ = SymbolicValue.symbolic(
            f"{getattr(left, 'name', 'a')}%{getattr(right, 'name', 'b')}"
        )
    state = state.push(result)
    state = state.advance_pc()
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
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_LSHIFT", "BINARY_RSHIFT")
def handle_binary_shift(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Binary shift operations with overflow and negative-shift checks."""
    right = state.pop()
    left = state.pop()
    op = "<<" if instr.opname == "BINARY_LSHIFT" else ">>"
    if not isinstance(left, SymbolicValue):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, SymbolicValue):
        right = SymbolicValue.from_const(right)
    issues: list[Issue] = []

    issues = check_negative_shift(right, state, op, left)

    state = state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int >= 0))

    left_bv = int_to_bv(left.z3_int)
    right_bv = int_to_bv(right.z3_int)
    result_bv = left_bv << right_bv if instr.opname == "BINARY_LSHIFT" else left_bv >> right_bv
    result = SymbolicValue(
        _name=f"({left.name}{op}{right.name})",
        z3_int=bv_to_int(result_bv),
        is_int=z3.And(left.is_int, right.is_int),
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        taint_labels=merge_taint(left.taint_labels, right.taint_labels),
    )
    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_AND")
def handle_binary_and(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise/logical AND."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, SymbolicValue):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, SymbolicValue):
        right = SymbolicValue.from_const(right)

    result = left & right
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_OR")
def handle_binary_or(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Bitwise/logical OR."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, SymbolicValue):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, SymbolicValue):
        right = SymbolicValue.from_const(right)

    result = left | right
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_XOR")
def handle_binary_xor(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Bitwise XOR."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, SymbolicValue):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, SymbolicValue):
        right = SymbolicValue.from_const(right)

    result = left ^ right
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _get_binop_result(
    left: SymbolicValue | SymbolicString,
    right: SymbolicValue | SymbolicString,
    op_code: str,
    state: VMState,
) -> tuple[StackValue | None, list[Issue], bool]:
    issues: list[Issue] = []
    terminal = False
    result = None

    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        if op_code in {"+", "+="}:
            result = left + right
        elif op_code in {"-", "-="}:
            result = left - right
        elif op_code in {"*", "*="}:
            result = left * right
        elif op_code in {"/", "/=", "//", "//=", "%", "%="}:
            op = op_code.replace("=", "")
            issues = check_division_by_zero(right, state, op, left)
            if _is_concrete_zero_divisor(right):
                return None, issues, True
            state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int != 0))
            if op == "/":
                result = left / right
            elif op == "//":
                result = left // right
            else:
                result = left % right
        elif op_code in {"**", "**="}:
            result = left**right
        elif op_code in {"&", "&=", "|", "|=", "^", "^="}:
            if op_code.startswith("&"):
                result = left & right
            elif op_code.startswith("|"):
                result = left | right
            else:
                result = left ^ right
        elif op_code in {"<<", "<<=", ">>", ">>="}:
            issues = check_negative_shift(right, state, op_code, left)
            state.add_constraint(z3.Or(z3.Not(right.is_int), right.z3_int >= 0))
            left_bv = int_to_bv(left.z3_int)
            right_bv = int_to_bv(right.z3_int)
            res_bv = left_bv << right_bv if op_code.startswith("<<") else left_bv >> right_bv
            result = SymbolicValue(
                _name=f"({left.name}{op_code}{right.name})",
                z3_int=bv_to_int(res_bv),
                is_int=z3.And(left.is_int, right.is_int),
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                taint_labels=merge_taint(left.taint_labels, right.taint_labels),
            )
    elif (
        isinstance(left, SymbolicString)
        and isinstance(right, SymbolicString)
        and op_code in {"+", "+="}
    ):
        result = left + right
    elif isinstance(left, SymbolicString) and op_code in {"%", "%="}:
        # BUG-007 fix: string % args formatting is valid Python — don't emit
        # a TypeError.  Produce a fresh symbolic string as the result.
        result, _ = SymbolicValue.symbolic(f"str_format_{state.pc}")

    if result is None:
        if op_code in ("+", "+=", "-", "-=", "*", "*=", "/", "/=", "//", "//=", "%", "%="):
            type_error_cond = list(state.path_constraints)
            if is_satisfiable(type_error_cond):
                issues.append(
                    Issue(
                        kind=IssueKind.TYPE_ERROR,
                        message=f"TypeError: unsupported operand type(s) for {op_code}: '{getattr(left, 'name', 'a')}' and '{getattr(right, 'name', 'b')}'",
                        constraints=type_error_cond,
                        model=get_model(type_error_cond),
                        pc=state.pc,
                    )
                )

                terminal = True

        if not terminal:
            result, _ = SymbolicValue.symbolic(f"binop_{state.pc}_fallback")

    return result, issues, terminal


@opcode_handler("BINARY_OP")
def handle_binary_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unified binary operation (Python 3.11+)."""
    right = state.pop()
    left = state.pop()
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)

    result, issues, terminal = _get_binop_result(left, right, instr.argrepr, state)
    if terminal:
        return OpcodeResult(new_states=[], issues=issues, terminal=True)

    state.push(result)
    state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)
