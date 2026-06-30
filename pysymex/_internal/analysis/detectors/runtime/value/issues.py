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

"""Shared satisfiable-path issue construction for the ValueError detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState


def satisfiable_path_evidence(
    state: VMState,
    solver_check: IsSatFn,
) -> tuple[list[z3.BoolRef], z3.ModelRef | dict[str, object]] | None:
    """Return satisfiable path constraints and model evidence, if available."""
    constraints = list(state.path_constraints)
    model = get_model_if_satisfiable_result(constraints, solver_check).model
    if model is None:
        return None
    return constraints, model


def value_error_issue(state: VMState, solver_check: IsSatFn, message: str) -> Issue | None:
    """Return a ValueError issue when the current path is satisfiable."""
    sat_evidence = satisfiable_path_evidence(state, solver_check)
    if sat_evidence is None:
        return None
    constraints, model = sat_evidence
    return Issue(
        kind=IssueKind.VALUE_ERROR,
        message=message,
        constraints=constraints,
        model=model,
        pc=state.pc,
    )
