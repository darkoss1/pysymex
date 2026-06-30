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

"""COMPARE_OP orchestration shared across Python versions.

This module remains the public import owner for comparison-family opcode
handlers. Rich comparison lowering stays here so tests and callers can
monkeypatch :data:`PathSatisfiability.is_sat`; identity and membership opcodes delegate to
specialized modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import resolve_compare_op_symbol
from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.exceptions.policy import type_error
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    degraded_passes_from_events,
    may_be_feasible,
    terminal_result_with_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.compare.collections import (
    exact_list_comparison_condition,
)
from pysymex._internal.execution.opcodes.common.compare.exact import exact_equality_condition
from pysymex._internal.execution.opcodes.common.compare.guards import require_compare_stack_depth
from pysymex._internal.execution.opcodes.common.compare.protocols import (
    dispatch_modeled_rich_comparison,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.execution.opcodes.common.lowering.comparison import ComparisonLowerer
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def _path_satisfiability_result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    return PathSatisfiability.result(constraints, known_sat_prefix_len=known_sat_prefix_len)


COMPARE_TYPE_ERROR_FEASIBILITY_UNKNOWN = "compare_type_error_feasibility_unknown"
_COMPARE_TYPE_ERROR_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=COMPARE_TYPE_ERROR_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.compare",
    subject="comparison TypeError",
)


def _comparison_bool_value(state: VMState, condition: z3.BoolRef) -> SymbolicValue:
    """Build the canonical symbolic bool result for a comparison condition."""
    return SymbolicValue(
        _name=f"compare_{state.pc}",
        z3_int=z3.If(condition, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=condition,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )


def _continue_with_comparison_result(state: VMState, result: SymbolicValue) -> OpcodeResult:
    """Push a comparison result and advance execution."""
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _exact_comparison_result(
    state: VMState,
    left: StackValue,
    right: StackValue,
    op_name: str,
) -> OpcodeResult | None:
    """Return precise list/equality comparison when available."""
    condition = exact_list_comparison_condition(left, right, op_name, state)
    if condition is None:
        condition = exact_equality_condition(left, right, op_name)
    if condition is None:
        return None
    return _continue_with_comparison_result(state, _comparison_bool_value(state, condition))


def _comparison_type_error_branch_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    left: object,
    right: object,
    op_name: str,
    result: SymbolicValue,
    type_error_cond: z3.BoolRef,
) -> OpcodeResult | None:
    """Return TypeError/success branches when comparison lowering is conditionally unsafe."""
    if z3.is_false(type_error_cond):
        return _continue_with_comparison_result(state, result)

    path_constraints = state.path_constraints.to_list()
    known_prefix = StateConstraints.known_sat_prefix_len(state)
    type_error_result = _path_satisfiability_result(
        [*path_constraints, type_error_cond],
        known_sat_prefix_len=known_prefix,
    )
    if not may_be_feasible(type_error_result):
        return None

    handler_pc = ctx.find_exception_handler(instr.offset)
    not_error = z3.Not(type_error_cond)
    success_result = _path_satisfiability_result(
        [*path_constraints, not_error],
        known_sat_prefix_len=known_prefix,
    )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_COMPARE_TYPE_ERROR_FEASIBILITY_SPEC,
        branches=[
            FeasibilityBranch("type_error", type_error_result),
            FeasibilityBranch("success", success_result),
        ],
    )
    degraded_passes = degraded_passes_from_events(fallback_events)
    if may_be_feasible(success_result):
        success_state = state.fork().add_constraint(not_error)
        success_state = success_state.push(result)
        success_state = success_state.advance_pc()
        if handler_pc is None:
            return OpcodeResult.continue_with(
                success_state,
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )
        error_state = _comparison_type_error_handler_state(
            instr,
            state.fork().add_constraint(type_error_cond),
            ctx,
            left,
            right,
            op_name,
        )
        if error_state is None:
            return OpcodeResult.continue_with(
                success_state,
                degraded_passes=degraded_passes,
                fallback_events=fallback_events,
            )
        return OpcodeResult.branch(
            [success_state, error_state],
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )

    if handler_pc is None:
        return terminal_result_with_events(fallback_events)
    error_state = _comparison_type_error_handler_state(
        instr,
        state.fork().add_constraint(type_error_cond),
        ctx,
        left,
        right,
        op_name,
    )
    if error_state is None:
        return terminal_result_with_events(fallback_events)
    return OpcodeResult.continue_with(
        error_state,
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def handle_common_compare_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Comparison operation with symbolic TypeError branching."""
    require_compare_stack_depth(state, instr, 2, "COMPARE_OP operands")
    right = state.pop()
    left = state.pop()
    op_name = resolve_compare_op_symbol(instr)

    exact_result = _exact_comparison_result(state, left, right, op_name)
    if exact_result is not None:
        return exact_result

    modeled_result = dispatch_modeled_rich_comparison(state, ctx, left, right, op_name)
    if modeled_result is not None:
        return modeled_result

    result, type_error_cond = ComparisonLowerer(state.pc).lower(left, right, op_name)
    type_error_result = _comparison_type_error_branch_result(
        instr,
        state,
        ctx,
        left,
        right,
        op_name,
        result,
        type_error_cond,
    )
    if type_error_result is not None:
        return type_error_result
    return _continue_with_comparison_result(state, result)


def _comparison_type_error_handler_state(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    left: object,
    right: object,
    op_name: str,
) -> VMState | None:
    """Return a CPython-shaped handler state for a possible comparison ``TypeError``."""
    message = (
        f"unsupported comparison {op_name!r} between "
        f"{type(left).__name__!s} and {type(right).__name__!s}"
    )
    exc = type_error(message, state=state, instr=instr)
    return ExceptionFlow.jump_to_handler(state, ctx, instr.offset, exc)
