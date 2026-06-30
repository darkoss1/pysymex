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

"""BINARY_OP and unary numeric opcode semantics for the common handler layer.

Prefers modeled binary dunders, then :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue`
arithmetic with explicit division-by-zero forking. Power, shift, and bitwise
cases degrade to fresh integers when intervals are too wide, recording abstraction
pass identifiers on the resulting
:class:`~pysymex._internal.execution.dispatch.result.OpcodeResult`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    degraded_passes_from_events,
    terminal_result_with_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.numeric.dunder import try_binary_dunder_call
from pysymex._internal.execution.opcodes.common.numeric.exceptions import (
    jump_to_modeled_exception_handler,
)
from pysymex._internal.execution.opcodes.common.numeric.guards import division_by_zero_condition
from pysymex._internal.execution.opcodes.common.numeric.labels import (
    NUMERIC_ZERO_DIVISION_FEASIBILITY_UNKNOWN,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.containers import (
    try_container_binary_op,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.errors import (
    binary_none_type_error,
    binary_string_type_error,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.positive import (
    continue_precise_unary_positive_value,
    handle_precise_unary_positive,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.special import (
    handle_bitwise_op,
    handle_power_op,
    handle_shift_op,
)
from pysymex._internal.execution.opcodes.common.numeric.values import push_havoc_result
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

_NUMERIC_ZERO_DIVISION_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=NUMERIC_ZERO_DIVISION_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.numeric",
    subject="numeric zero-division",
)


def handle_numeric_binary_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute Python-faithful numeric ``BINARY_OP`` semantics."""
    op_symbol = resolve_binary_op_symbol(instr)
    if not op_symbol:
        state.pop()
        state.pop()
        return push_havoc_result(state, f"binop_havoc_{state.pc}")
    base_op = op_symbol.removesuffix("=")

    right = state.pop()
    left = state.pop()

    if base_op not in {"+", "-", "*", "/", "//", "%", "**", "<<", ">>", "&", "|", "^"}:
        return push_havoc_result(state, f"binop_havoc_{state.pc}")

    container_result = try_container_binary_op(state, left, right, op_symbol)
    if container_result is not None:
        return container_result

    dunder_result = try_binary_dunder_call(state, ctx, left, right, op_symbol)
    if dunder_result is not None:
        return dunder_result

    none_type_error = binary_none_type_error(instr, state, ctx, left, right, base_op)
    if none_type_error is not None:
        return none_type_error

    string_type_error = binary_string_type_error(instr, state, ctx, left, right, base_op)
    if string_type_error is not None:
        return string_type_error

    if isinstance(left, SymbolicString) or isinstance(right, SymbolicString):
        return push_havoc_result(state, f"binop_{base_op}_{state.pc}")

    left_value = SymbolicValue.from_const(left)
    right_value = SymbolicValue.from_const(right)

    if base_op in {"+", "-", "*", "/", "//", "%"}:
        return handle_standard_numeric_op(instr, state, ctx, left_value, right_value, base_op)
    if base_op == "**":
        return handle_power_op(state, left_value, right_value)
    if base_op in {"<<", ">>"}:
        return handle_shift_op(state, left_value, right_value, base_op)
    return handle_bitwise_op(state, left_value, right_value, base_op)


def handle_numeric_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute unary ``+`` (``UNARY_POSITIVE`` / intrinsic 5): pop and push ``+value``."""
    return handle_precise_unary_positive(instr, state, ctx)


def continue_numeric_unary_positive_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    value: object,
) -> OpcodeResult:
    """Apply unary ``+`` to a caller-supplied operand without an extra stack pop."""
    return continue_precise_unary_positive_value(instr, state, ctx, value)


def handle_numeric_unary_negative(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary negative semantics."""
    value = state.pop()
    if isinstance(value, (int, float, bool)):
        state = state.push(-value)
    else:
        symbolic = SymbolicValue.from_const(value)
        state = state.push(-symbolic)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_numeric_unary_not(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary ``not`` semantics."""
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    state = state.push(symbolic.logical_not())
    return OpcodeResult.continue_with(state.advance_pc())


def handle_numeric_unary_invert(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary invert semantics."""
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    result = symbolic.__invert__()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_standard_numeric_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Delegate arithmetic to ``SymbolicValue`` for faithful typing semantics."""
    if op_symbol in {"/", "//", "%"}:
        zero_condition = simplify_expr(division_by_zero_condition(right))
        if z3.is_false(zero_condition):
            return continue_standard_numeric_op(state, left, right, op_symbol)
        constraints = state.path_constraints.to_list()
        known_prefix = StateConstraints.known_sat_prefix_len(state)
        zero_result = PathSatisfiability.result(
            [*constraints, zero_condition],
            known_sat_prefix_len=known_prefix,
        )
        if not zero_result.is_unsat:
            nonzero_condition = z3.Not(zero_condition)
            nonzero_result = PathSatisfiability.result(
                [*constraints, nonzero_condition],
                known_sat_prefix_len=known_prefix,
            )
            fallback_events = unknown_feasibility_events(
                state=state,
                spec=_NUMERIC_ZERO_DIVISION_FEASIBILITY_SPEC,
                branches=[
                    FeasibilityBranch("zero", zero_result),
                    FeasibilityBranch("nonzero", nonzero_result),
                ],
            )
            degraded_passes = degraded_passes_from_events(fallback_events)
            states: list[VMState] = []
            if not nonzero_result.is_unsat:
                success_state = state.fork().add_constraint(nonzero_condition)
                success_result = continue_standard_numeric_op(
                    success_state,
                    left,
                    right,
                    op_symbol,
                )
                states.extend(success_result.new_states)

            handler_state = jump_to_modeled_exception_handler(
                state.fork().add_constraint(zero_condition),
                ctx,
                instr,
                "ZeroDivisionError",
                "modulo by zero" if op_symbol == "%" else "division by zero",
                confidence=_zero_division_confidence(right),
                likelihood=_zero_division_confidence(right),
            )
            if handler_state is not None:
                states.append(handler_state)

            if states:
                return OpcodeResult.branch(
                    states,
                    degraded_passes=degraded_passes,
                    fallback_events=fallback_events,
                )
            return terminal_result_with_events(fallback_events)

    return continue_standard_numeric_op(state, left, right, op_symbol)


def _zero_division_confidence(divisor: object) -> float:
    """Return issue confidence for a modeled zero-division exception."""
    if is_havoc(divisor):
        return 0.5
    return 1.0


def continue_standard_numeric_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Push the result of ``+``, ``-``, ``*``, ``/``, ``//``, or ``%`` and advance PC."""
    try:
        if op_symbol == "+":
            result = left + right
        elif op_symbol == "-":
            result = left - right
        elif op_symbol == "*":
            result = left * right
        elif op_symbol == "/":
            result = left / right
        elif op_symbol == "//":
            result = left // right
        else:
            result = left % right
    except ZeroDivisionError:
        return OpcodeResult.terminate()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())
