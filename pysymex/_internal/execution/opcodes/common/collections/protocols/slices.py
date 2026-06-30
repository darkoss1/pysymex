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

"""Retained slice protocol error routing for native collection opcodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import value_error
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
    possible_zero_step_condition,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    may_be_feasible,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

RETAINED_SLICE_ZERO_STEP_FEASIBILITY_UNKNOWN = "retained_slice_zero_step_feasibility_unknown"
_RETAINED_SLICE_ZERO_STEP_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=RETAINED_SLICE_ZERO_STEP_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="retained slice zero-step",
)


def retained_slice_value_error_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    message: str = "slice step cannot be zero",
    degraded_passes: list[str] | None = None,
) -> OpcodeResult:
    """Branch or error on a concrete ``ValueError`` for invalid retained slice bounds."""
    modeled_exc = value_error(message, state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, modeled_exc)
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=degraded_passes or [],
        reason="retained slice zero-step condition is possible but not definite",
    )
    if handler_state is not None:
        return OpcodeResult.continue_with(
            handler_state,
            degraded_passes=degraded_passes,
            fallback_events=fallback_events,
        )
    return OpcodeResult.error(
        Issue(
            kind=IssueKind.VALUE_ERROR,
            message=f"Possible ValueError: {message}",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def dispatch_retained_slice_zero_step(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    index: SymbolicValue,
) -> OpcodeResult | None:
    """Report or route the feasible ``step == 0`` path of a retained slice."""
    condition = possible_zero_step_condition(index)
    if condition is None:
        return None
    result = PathSatisfiability.result(
        [*state.path_constraints, condition],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
    if not may_be_feasible(result):
        return None
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_RETAINED_SLICE_ZERO_STEP_FEASIBILITY_SPEC,
        branches=[FeasibilityBranch("zero_step", result)],
    )
    is_definite = z3.is_true(simplify_expr(condition))
    error_state = state.fork().add_constraint(condition)
    return append_fallback_events(
        retained_slice_value_error_result(
            instr,
            error_state,
            ctx,
            degraded_passes=None if is_definite else [UNSUPPORTED_SLICE_ABSTRACTION],
        ),
        fallback_events,
    )
