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

"""Issue publication for uncaught modeled potential exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.execution.model.effects.core import issues_from_model_side_effects

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.calls.model.exceptions.types import PathFeasibilityPredicate
    from pysymex._internal.models.contracts.results import PotentialException


def issues_from_uncaught_potential_effects(
    state: VMState,
    effects: list[PotentialException],
    success_condition: z3.BoolRef,
    reportable_path_is_sat: PathFeasibilityPredicate,
) -> list[Issue]:
    """Publish uncaught modeled exceptions left over after handler branching."""
    adjusted_effects: list[dict[str, object]] = []
    for effect in effects:
        adjusted_effects.append(
            {
                "type": effect["type"],
                "message": effect["message"],
                "condition": z3.And(effect["condition"], success_condition),
            },
        )
    if not adjusted_effects:
        return []
    return issues_from_model_side_effects(
        {"potential_exceptions": adjusted_effects},
        state.pc,
        path_constraints=list(state.path_constraints),
        path_may_be_feasible=reportable_path_is_sat,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )
