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

"""Handler and success-path branching for conditional modeled exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.exceptions.policy import runtime_exception
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.execution.calls.model.exceptions.classification import (
    potential_exception_is_caught,
)
from pysymex._internal.execution.calls.model.exceptions.issues import (
    issues_from_uncaught_potential_effects,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    degraded_passes_from_events,
    may_be_feasible,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.models.contracts.results import (
    PotentialException,
    SideEffects,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.calls.model.exceptions.types import PathFeasibilityPredicate
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.models.builtins.registry.models import RegisteredResult

MODEL_POTENTIAL_EXCEPTION_FEASIBILITY_UNKNOWN = "model_potential_exception_feasibility_unknown"
_MODEL_POTENTIAL_EXCEPTION_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=MODEL_POTENTIAL_EXCEPTION_FEASIBILITY_UNKNOWN,
    owner="execution.calls.model.exceptions",
    subject="modeled potential-exception",
)


def branch_on_caught_potential_exception(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction | None,
    result: RegisteredResult,
    reportable_path_is_sat: PathFeasibilityPredicate,
) -> OpcodeResult | None:
    """Fork success and handler paths for modeled potential-exception side effects."""
    if ctx is None or instr is None or not result.side_effects:
        return None

    branches: list[VMState] = []
    caught_conditions: list[z3.BoolRef] = []
    uncaught_effects: list[PotentialException] = []
    feasibility_branches: list[FeasibilityBranch] = []
    for effect in _potential_exception_effects(result):
        condition = effect["condition"]
        exception_result = _potential_exception_feasibility_result(state, condition)
        feasibility_branches.append(FeasibilityBranch("exception", exception_result))
        if not may_be_feasible(exception_result):
            continue

        if potential_exception_is_caught(state, ctx, instr, effect):
            handler_state = ExceptionFlow.jump_to_handler(
                state.fork().add_constraint(condition),
                ctx,
                instr.offset,
                runtime_exception(
                    effect["type"],
                    message=effect["message"],
                    state=state,
                    instr=instr,
                    condition=condition,
                ),
            )
            if handler_state is not None:
                branches.append(handler_state)
                caught_conditions.append(condition)
                continue

        uncaught_effects.append(effect)

    if not branches:
        return None

    success_condition = _none_of(caught_conditions)
    success_result = _potential_exception_feasibility_result(state, success_condition)
    feasibility_branches.append(FeasibilityBranch("success", success_result))
    if may_be_feasible(success_result):
        success_state = _push_model_success(
            state.fork().add_constraint(success_condition),
            result,
        )
        branches.insert(0, success_state)

    issues = issues_from_uncaught_potential_effects(
        state,
        uncaught_effects,
        success_condition,
        reportable_path_is_sat,
    )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_MODEL_POTENTIAL_EXCEPTION_FEASIBILITY_SPEC,
        branches=feasibility_branches,
    )
    return OpcodeResult.branch(
        branches,
        issues,
        degraded_passes=degraded_passes_from_events(fallback_events),
        fallback_events=fallback_events,
    )


def _potential_exception_feasibility_result(
    state: VMState,
    condition: z3.BoolRef,
) -> SolverResult:
    """Return structured feasibility evidence for a modeled exception branch."""
    return check_sat_result(
        [*state.path_constraints, condition],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )


def _potential_exception_effects(result: RegisteredResult) -> list[PotentialException]:
    """Return all well-formed potential-exception effects on a model result."""
    effects: list[PotentialException] = []
    single_effect = result.side_effects.get("potential_exception")
    if SideEffects.is_potential_exception(single_effect):
        effects.append(single_effect)
    effect_sequence = result.side_effects.get("potential_exceptions")
    if SideEffects.is_potential_exception_sequence(effect_sequence):
        effects.extend(effect_sequence)
    return effects


def _none_of(conditions: list[z3.BoolRef]) -> z3.BoolRef:
    """Return a condition that excludes every condition in *conditions*."""
    if len(conditions) == 1:
        return z3.Not(conditions[0])
    return z3.Not(z3.Or(*conditions))


def _push_model_success(state: VMState, result: RegisteredResult) -> VMState:
    """Push a modeled return value and advance past the calling opcode."""
    state = state.push(result.value)
    for constraint in result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return state.advance_pc()
