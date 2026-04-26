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
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.execution.opcodes.py313.control import get_truthy_expr

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
                    and (
                        z3.is_true(left.is_str)
                        or str(left.is_str) == "True"
                        or left.affinity_type == "str"
                    )
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
    # Check if stack has at least 2 elements to prevent stack underflow
    if len(state.stack) < 2:
        # Stack is empty, use symbolic values
        sym_val, type_constraint = SymbolicValue.symbolic(f"binary_op_{state.pc}")
        state = state.add_constraint(type_constraint)
        result = sym_val
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    left = state.pop()
    right = state.pop()
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
        if any(i.kind == IssueKind.DIVISION_BY_ZERO and not i.constraints for i in pre_issues):
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
                from pysymex.core.exceptions.analyzer import SymbolicException

                exc_obj = SymbolicException.concrete(
                    ZeroDivisionError, "division by zero", state.pc
                )
                exc_state = state.set_pc(handler_pc).push(exc_obj)
                return OpcodeResult(new_states=[exc_state], issues=pre_issues)
            return OpcodeResult(new_states=[], issues=pre_issues, terminal=True)

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

            zero_cond = z3.Or(
                z3.And(right.is_int, right.z3_int == 0),
                z3.And(right.is_float, z3.fpIsZero(right.z3_float)),
            )
            exc_state = state.fork()
            exc_state = exc_state.add_constraint(zero_cond)

            if handler_pc is not None:
                from pysymex.core.exceptions.analyzer import SymbolicException

                exc_obj = SymbolicException.symbolic(
                    f"div_zero_{state.pc}", ZeroDivisionError, zero_cond, state.pc
                )
                exc_state = exc_state.set_pc(handler_pc).push(exc_obj)
                new_states = [exc_state]
            else:
                new_states = []

            normal_state = state.add_constraint(z3.Not(zero_cond))
            result, issues, terminal = _get_binop_result(left, right, instr.argrepr, normal_state)

            all_issues = pre_issues + issues

            if terminal or result is None:
                return OpcodeResult(new_states=new_states, issues=all_issues)

            normal_state = normal_state.push(result)
            normal_state = normal_state.advance_pc()
            new_states.append(normal_state)
            return OpcodeResult(new_states=new_states, issues=all_issues)

    result, issues, terminal = _get_binop_result(left, right, instr.argrepr, state)
    if terminal:
        return OpcodeResult(new_states=[], issues=issues, terminal=True)

    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_ZERO_SUPER_ATTR", "LOAD_ZERO_SUPER_METHOD")
def handle_load_zero_super(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle LOAD_ZERO_SUPER_ATTR and LOAD_ZERO_SUPER_METHOD (Python 3.12+)."""
    attr_name = str(instr.argval)

    val, type_constraint = SymbolicValue.symbolic(f"super_attr_{attr_name}@{state.pc}")
    state = state.add_constraint(type_constraint)
    state = state.push(val)

    if instr.opname == "LOAD_ZERO_SUPER_METHOD" or (
        hasattr(instr, "arg") and instr.arg is not None and (instr.arg & 1)
    ):
        from pysymex.core.types.scalars import SymbolicNone

        state = state.push(SymbolicNone())

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_ATTR")
def handle_load_attr(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle LOAD_ATTR."""
    attr_name = str(instr.argval)
    _ = state.pop()

    val, type_constraint = SymbolicValue.symbolic(f"attr_{attr_name}@{state.pc}")
    state = state.add_constraint(type_constraint)
    state = state.push(val)

    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            from pysymex.core.types.scalars import SymbolicNone

            state = state.push(SymbolicNone())

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
