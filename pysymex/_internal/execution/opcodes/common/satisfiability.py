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

"""Opcode-layer satisfiability checks for path constraints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.engine.policies import path_may_be_feasible
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.solver.engine.results import SolverResult

if TYPE_CHECKING:
    import z3


def _is_sat(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return whether *constraints* may be satisfiable on the current path."""
    filtered_constraints, nontrivial_known_prefix_len, has_literal_unsat = (
        _filter_literal_constraints(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
    )
    if has_literal_unsat:
        return False
    if not filtered_constraints:
        return True
    if known_sat_prefix_len is None:
        return path_may_be_feasible(filtered_constraints)
    return path_may_be_feasible(
        filtered_constraints,
        known_sat_prefix_len=nontrivial_known_prefix_len,
    )


def _result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    """Return structured SAT evidence for an opcode-layer path check."""
    filtered_constraints, nontrivial_known_prefix_len, has_literal_unsat = (
        _filter_literal_constraints(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
    )
    if has_literal_unsat:
        return SolverResult.unsat()
    if not filtered_constraints:
        return SolverResult.sat(None)
    if known_sat_prefix_len is None:
        return check_sat_result(filtered_constraints)
    return check_sat_result(
        filtered_constraints,
        known_sat_prefix_len=nontrivial_known_prefix_len,
    )


def _filter_literal_constraints(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None,
) -> tuple[list[z3.BoolRef], int, bool]:
    """Strip exact true literals and detect exact false literals."""
    nontrivial_constraints_reversed: list[z3.BoolRef] = []
    nontrivial_known_prefix_len = 0
    known_prefix_limit = (
        len(constraints)
        if known_sat_prefix_len is None
        else max(0, min(known_sat_prefix_len, len(constraints)))
    )
    for index in range(len(constraints) - 1, -1, -1):
        constraint = constraints[index]
        literal = exact_bool_literal(constraint)
        if literal is False:
            return [], 0, True
        if literal is not True:
            nontrivial_constraints_reversed.append(constraint)
            if index < known_prefix_limit:
                nontrivial_known_prefix_len += 1
    nontrivial_constraints_reversed.reverse()
    return nontrivial_constraints_reversed, nontrivial_known_prefix_len, False


class PathSatisfiability:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    is_sat = staticmethod(_is_sat)
    result = staticmethod(_result)
