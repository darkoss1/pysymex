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

"""Solver and witness fallback policy for detector SAT queries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.feasibility import detector_witness_model
from pysymex._internal.analysis.evidence.floats import zero_float_witness_model
from pysymex._internal.execution.detectors.query.cache.decisions import DetectorQueryDecision
from pysymex._internal.execution.detectors.query.retry import model_backed_detector_query

if TYPE_CHECKING:
    import z3

    from pysymex._internal.typing.protocols import SolverProtocol


def solver_detector_query_decision(
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> DetectorQueryDecision:
    """Return a detector-query decision from witnesses, solver status, or UNKNOWN fallback."""
    if zero_float_witness_model(constraints) is not None:
        return DetectorQueryDecision(
            result=True,
            result_source="zero_float_witness",
            witness_used=True,
        )

    result = solver.check_sat_result(constraints, known_sat_prefix_len=known_sat_prefix_len)
    if result.is_sat or result.is_unsat:
        return DetectorQueryDecision(
            result=result.is_sat,
            result_source="solver_sat" if result.is_sat else "solver_unsat",
            witness_used=False,
        )

    if detector_witness_model(constraints) is not None:
        return DetectorQueryDecision(
            result=True,
            result_source="witness_after_solver_unknown",
            witness_used=True,
        )

    model_result = model_backed_detector_query(solver, constraints)
    if model_result.is_sat or model_result.is_unsat:
        return DetectorQueryDecision(
            result=model_result.is_sat,
            result_source="solver_sat" if model_result.is_sat else "solver_unsat",
            witness_used=False,
        )

    return DetectorQueryDecision(
        result=False,
        result_source="solver_unknown",
        witness_used=False,
        cacheable=False,
    )
