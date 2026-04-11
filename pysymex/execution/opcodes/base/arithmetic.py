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

"""Arithmetic and binary operation opcodes."""

from __future__ import annotations

import dis
import logging
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.checks import is_overloaded_arithmetic
from pysymex.core.types.scalars import (
    Z3_FALSE,
    SymbolicString,
    SymbolicValue,
    merge_taint,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.execution.opcodes.base.control import get_truthy_expr

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
    """Verify if the current path constraints allow the divisor to be zero.

    **Verification Semantics:**
    This check executes a specialized Z3 satisfiability query:
    `PC ∧ ((right is int ∧ right == 0) ∨ (right is float ∧ right == 0.0))`.

    If the solver returns `SAT`, it indicates a feasible execution path where
    a `ZeroDivisionError` would occur in a concrete Python VM. The check
    is performed *before* the engine's self-preservation constraints are
    added, ensuring the reported Z3 model is a valid application counterexample.

    Args:
        right: The symbolic divisor to be validated.
        state: VM state providing the global path constraints.
        op_name: Human-readable operator (e.g., "/", "%", "//").
        left: The dividend (used for issue localization/reporting).

    Returns:
        A list of `Issue` objects representing detected vulnerabilities.
    """
    issues: list[Issue] = []

    if is_overloaded_arithmetic(left, right):
        return []

    if z3.is_int_value(right.z3_int) and right.z3_int.as_long() == 0:
        issues.append(
            Issue(
                kind=IssueKind.DIVISION_BY_ZERO,
                message=f"Division by zero: {left.name} {op_name} {right.name}",
                constraints=[],
                model=None,
                pc=state.pc,
            )
        )
        return issues

    zero_check = [
        *state.path_constraints,
        z3.Or(
            z3.And(right.is_int, right.z3_int == 0),
            z3.And(right.is_float, z3.fpIsZero(right.z3_float)),
        ),
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
    """Check if the bitwise shift count could be negative.

    **Verification Semantics:**
    Python's `<<` and `>>` operators raise `ValueError` for negative shift
    counts. This method queries Z3 for `PC ∧ right is int ∧ right < 0`.

    Args:
        right: Symbolic shift count to test.
        state: Current VM state with path constraints.
        op_name: Operator string ("<<" or ">>").
        left: Value being shifted, used for the error message.

    Returns:
        List of Issue objects if a negative shift is satisfiable.
    """
    issues: list[Issue] = []

    if z3.is_int_value(right.z3_int):
        if right.z3_int.as_long() < 0:
            issues.append(
                Issue(
                    kind=IssueKind.VALUE_ERROR,
                    message=f"Definite negative shift count: {left.name} {op_name} {right.name}",
                    constraints=[],
                    model=None,
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


def _bv_shift(left: z3.ArithRef, right: z3.ArithRef, is_lshift: bool) -> z3.ArithRef:
    """Compute shift safely using BitVectors to avoid non-linear arithmetic explosions."""
    from pysymex.core.types.scalars import BV_WIDTH, bv_to_int, int_to_bv

    safe_right = z3.If(right > BV_WIDTH - 1, z3.IntVal(BV_WIDTH - 1), right)

    left_bv = int_to_bv(left)
    right_bv = int_to_bv(safe_right)

    if is_lshift:
        result_bv = left_bv << right_bv
    else:
        result_bv = left_bv >> right_bv

    return bv_to_int(result_bv)


@opcode_handler("UNARY_POSITIVE")
def handle_unary_positive(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Implement the ``+x`` unary operator.

    **Emulation Logic:**
    While numeric identity holds for `int` and `float`, the opcode must still
    obey Python's stack semantics—popping the operand and re-pushing it.
    This ensures functional consistency with the Python VM's object model.
    """
    top = state.pop()
    state = state.push(top)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_NEGATIVE")
def handle_unary_negative(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Implement the ``-x`` unary negation operator."""
    top = state.pop()
    if isinstance(top, SymbolicValue):
        state = state.push(-top)
    else:
        state = state.push(-top if isinstance(top, (int, float)) else top)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNARY_NOT")
def handle_unary_not(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Implement the ``not x`` boolean negation operator.

    Calculates the logical inversion based on the object's potential truthiness.
    """
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
    """Implement the ``~x`` bitwise NOT (inversion) operator."""
    top = state.pop()
    if isinstance(top, SymbolicValue) or (isinstance(top, int) and not isinstance(top, bool)):
        state = state.push(~top)
    else:
        state = state.push(top)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_ADD")
def handle_binary_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Implement the ``+`` binary addition operator."""
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
            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.Not(z3.And(*type_error_cond[len(state.path_constraints) :])),
                ]
            ):
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
    """Implement the ``-`` binary subtraction operator."""
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
            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.Not(z3.And(*type_error_cond[len(state.path_constraints) :])),
                ]
            ):
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
    """Implement the ``*`` binary multiplication operator."""
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
            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.Not(z3.And(*type_error_cond[len(state.path_constraints) :])),
                ]
            ):
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
    """Implement division (``/``, ``//``) with safety checks.

    When the divisor could be zero and the instruction is inside a
    try/except block, forks into two paths: one where the divisor is
    non-zero (normal continuation) and one where it is zero (jumps to
    the exception handler).
    """
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

        has_div_zero_issue = any(i.kind == IssueKind.DIVISION_BY_ZERO for i in issues)
        handler_pc = None
        if has_div_zero_issue:
            handler_pc = ctx.find_exception_handler(instr.offset)

            if handler_pc is None:
                block = state.current_block()
                if (
                    block
                    and block.block_type in ("finally", "except", "cleanup")
                    and block.handler_pc is not None
                ):
                    handler_pc = block.handler_pc

        if handler_pc is not None:
            zero_cond = z3.Or(
                z3.And(right.is_int, right.z3_int == 0),
                z3.And(right.is_float, z3.fpIsZero(right.z3_float)),
            )

            exc_state = state.fork()
            exc_state = exc_state.add_constraint(zero_cond)
            exc_state = exc_state.set_pc(handler_pc)

            normal_state = state.add_constraint(z3.Not(zero_cond))
            result = left / right if instr.opname == "BINARY_TRUE_DIVIDE" else left // right
            normal_state = normal_state.push(result)
            normal_state = normal_state.advance_pc()

            return OpcodeResult(new_states=[normal_state, exc_state], issues=issues)

        state = state.add_constraint(
            z3.And(
                z3.Or(z3.Not(right.is_int), right.z3_int != 0),
                z3.Or(z3.Not(right.is_float), z3.Not(z3.fpIsZero(right.z3_float))),
            )
        )
        result = left / right if instr.opname == "BINARY_TRUE_DIVIDE" else left // right
    else:
        type_error_cond = [
            *state.path_constraints,
            z3.Not(z3.And(getattr(left, "is_int", Z3_FALSE), getattr(right, "is_int", Z3_FALSE))),
        ]
        if is_satisfiable(type_error_cond):
            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.Not(z3.And(*type_error_cond[len(state.path_constraints) :])),
                ]
            ):
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
    """Implement bitwise modulo (``%``) or string formatting."""
    right = state.pop()
    left = state.pop()

    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)

    new_states = []

    if isinstance(left, SymbolicString) or is_satisfiable([*state.path_constraints, left.is_str]):
        s_state = state.copy()
        if isinstance(left, SymbolicValue):
            s_state = s_state.add_constraint(left.is_str)

        result, _ = SymbolicString.symbolic(f"str_format_{state.pc}")
        s_state = s_state.push(result)
        s_state = s_state.advance_pc()
        new_states.append(s_state)

    if not isinstance(left, SymbolicString) and is_satisfiable(
        [*state.path_constraints, z3.Not(left.is_str)]
    ):
        m_state = state.copy()
        m_state = m_state.add_constraint(z3.Not(left.is_str))

        m_issues = []
        if isinstance(right, SymbolicValue):
            m_issues = check_division_by_zero(right, m_state, "%", left)
            if _is_concrete_zero_divisor(right):
                if not new_states:
                    return OpcodeResult(new_states=[], issues=m_issues, terminal=True)

            else:
                m_state = m_state.add_constraint(
                    z3.And(
                        z3.Or(z3.Not(right.is_int), right.z3_int != 0),
                        z3.Or(z3.Not(right.is_float), z3.Not(z3.fpIsZero(right.z3_float))),
                    )
                )
                result = left % right
                m_state = m_state.push(result)
                m_state = m_state.advance_pc()
                new_states.append(m_state)
        else:
            result, _ = SymbolicValue.symbolic(
                f"{getattr(left, '_name', 'a')}%{getattr(right, '_name', 'b')}"
            )
            m_state = m_state.push(result)
            m_state = m_state.advance_pc()
            new_states.append(m_state)

        if m_issues:
            return OpcodeResult(new_states=new_states, issues=m_issues)

    if not new_states:
        return OpcodeResult.error(
            Issue(
                IssueKind.TYPE_ERROR, "Invalid modulo operands", list(state.path_constraints), None
            ),
            state,
        )

    return OpcodeResult(new_states=new_states, issues=[])


@opcode_handler("BINARY_POWER")
def handle_binary_power(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Implement the ``**`` binary exponentiation operator."""
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
    """Implement bitwise shift (``<<``, ``>>``) with negative count checks."""
    right = state.pop()
    left = state.pop()
    op = "<<" if instr.opname == "BINARY_LSHIFT" else ">>"
    if not isinstance(left, SymbolicValue):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, SymbolicValue):
        right = SymbolicValue.from_const(right)
    issues: list[Issue] = []

    issues = check_negative_shift(right, state, op, left)

    type_error_cond = [
        *state.path_constraints,
        z3.Or(z3.Not(left.is_int), z3.Not(right.is_int)),
    ]
    if is_satisfiable(type_error_cond):
        issues.append(
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message=f"TypeError: unsupported operand type(s) for {op}: '{left.name}' and '{right.name}'",
                constraints=type_error_cond,
                model=get_model(type_error_cond),
                pc=state.pc,
            )
        )

    int_path = [*state.path_constraints, left.is_int, right.is_int]
    if not is_satisfiable(int_path):
        return OpcodeResult(new_states=[], issues=issues, terminal=True)

    state = state.add_constraint(z3.And(left.is_int, right.is_int, right.z3_int >= 0))

    res_int = _bv_shift(left.z3_int, right.z3_int, is_lshift=(instr.opname == "BINARY_LSHIFT"))

    result = SymbolicValue(
        _name=f"({left.name}{op}{right.name})",
        z3_int=res_int,
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
    """Implement the ``&`` bitwise/logical AND operator."""
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
    """Implement the ``|`` bitwise/logical OR operator."""
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
    """Implement the ``^`` bitwise XOR operator."""
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
    """Calculate the result of a binary operation for unified handling."""
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
            is_str_format = False
            if op == "%":
                if isinstance(left, SymbolicString) or (
                    hasattr(left, "is_str")
                    and (left.is_str == z3.BoolVal(True) or left.affinity_type == "str")
                ):
                    is_str_format = True

            if is_str_format:
                result, _ = SymbolicString.symbolic(f"str_format_{state.pc}")
            else:
                issues = check_division_by_zero(right, state, op, left)
                if _is_concrete_zero_divisor(right):
                    return None, issues, True
                state = state.add_constraint(
                    z3.And(
                        z3.Or(z3.Not(right.is_int), right.z3_int != 0),
                        z3.Or(z3.Not(right.is_float), z3.Not(z3.fpIsZero(right.z3_float))),
                    )
                )
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
            type_error_cond = [
                *state.path_constraints,
                z3.Or(z3.Not(left.is_int), z3.Not(right.is_int)),
            ]
            if is_satisfiable(type_error_cond):
                issues.append(
                    Issue(
                        kind=IssueKind.TYPE_ERROR,
                        message=f"TypeError: unsupported operand type(s) for {op_code}: '{left.name}' and '{right.name}'",
                        constraints=type_error_cond,
                        model=get_model(type_error_cond),
                        pc=state.pc,
                    )
                )

            int_path = [*state.path_constraints, left.is_int, right.is_int]
            if not is_satisfiable(int_path):
                return None, issues, True

            state = state.add_constraint(z3.And(left.is_int, right.is_int, right.z3_int >= 0))
            res_int = _bv_shift(left.z3_int, right.z3_int, is_lshift=op_code.startswith("<<"))

            result = SymbolicValue(
                _name=f"({left.name}{op_code}{right.name})",
                z3_int=res_int,
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
        result, _ = SymbolicString.symbolic(f"str_format_{state.pc}")

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
    """Unified binary operation handler (Python 3.11+).

    For division ops inside try/except, forks into normal + exception paths.
    """
    right = state.pop()
    left = state.pop()
    if not isinstance(left, (SymbolicValue, SymbolicString)):
        left = SymbolicValue.from_const(left)
    if not isinstance(right, (SymbolicValue, SymbolicString)):
        right = SymbolicValue.from_const(right)

    is_div_op = instr.argrepr in {"/", "/=", "//", "//=", "%", "%="}
    has_div_zero_issue = False
    handler_pc = None

    if is_div_op and isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        pre_issues = check_division_by_zero(right, state, instr.argrepr.replace("=", ""), left)
        has_div_zero_issue = any(i.kind == IssueKind.DIVISION_BY_ZERO for i in pre_issues)
        if has_div_zero_issue:
            handler_pc = ctx.find_exception_handler(instr.offset)
            if handler_pc is None:
                block = state.current_block()
                if (
                    block
                    and block.block_type in ("finally", "except", "cleanup")
                    and block.handler_pc is not None
                ):
                    handler_pc = block.handler_pc

    if handler_pc is not None and isinstance(right, SymbolicValue):
        zero_cond = z3.Or(
            z3.And(right.is_int, right.z3_int == 0),
            z3.And(right.is_float, z3.fpIsZero(right.z3_float)),
        )
        exc_state = state.fork()
        exc_state = exc_state.add_constraint(zero_cond)
        exc_state = exc_state.set_pc(handler_pc)

        normal_state = state.add_constraint(z3.Not(zero_cond))
        result, issues, terminal = _get_binop_result(left, right, instr.argrepr, normal_state)
        if terminal or result is None:
            return OpcodeResult(new_states=[exc_state], issues=issues)
        normal_state = normal_state.push(result)
        normal_state = normal_state.advance_pc()
        return OpcodeResult(new_states=[normal_state, exc_state], issues=issues)

    result, issues, terminal = _get_binop_result(left, right, instr.argrepr, state)
    if terminal:
        return OpcodeResult(new_states=[], issues=issues, terminal=True)

    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)
