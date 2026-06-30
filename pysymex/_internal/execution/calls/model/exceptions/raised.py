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

"""Handler branching for definite modeled exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.exceptions.policy import runtime_exception
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.execution.calls.model.exceptions.classification import (
    modeled_exception_type,
    raised_model_exception_is_caught,
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
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.models.builtins.registry.models import RegisteredResult

MODEL_RAISED_EXCEPTION_FEASIBILITY_UNKNOWN = "model_raised_exception_feasibility_unknown"
_MODEL_RAISED_EXCEPTION_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=MODEL_RAISED_EXCEPTION_FEASIBILITY_UNKNOWN,
    owner="execution.calls.model.exceptions",
    subject="modeled raised-exception path",
)


def branch_on_caught_raised_exception(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction | None,
    result: RegisteredResult,
) -> OpcodeResult | None:
    """Enter an exception handler for definite modeled exceptions when one exists."""
    if ctx is None or instr is None or not result.side_effects:
        return None
    effect = result.side_effects.get("raised_exception")
    if not SideEffects.is_raised_exception(effect):
        return None
    if not raised_model_exception_is_caught(state, ctx, instr, effect):
        return None

    handler_state = ExceptionFlow.jump_to_handler(
        state.fork(),
        ctx,
        instr.offset,
        runtime_exception(
            modeled_exception_type(effect["exception_type"]),
            message=effect["message"],
            state=state,
            instr=instr,
        ),
    )
    if handler_state is None:
        return None

    feasibility_result = _raised_exception_feasibility_result(state)
    if not may_be_feasible(feasibility_result):
        return None
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_MODEL_RAISED_EXCEPTION_FEASIBILITY_SPEC,
        branches=[FeasibilityBranch("handler", feasibility_result)],
    )
    return OpcodeResult.continue_with(
        handler_state,
        degraded_passes=degraded_passes_from_events(fallback_events),
        fallback_events=fallback_events,
    )


def _raised_exception_feasibility_result(state: VMState) -> SolverResult:
    """Return structured feasibility evidence for a modeled raised-exception path."""
    return check_sat_result(
        state.path_constraints.to_list(),
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
