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

"""Z3 expression and constraint simplification helpers."""

from __future__ import annotations

import z3

from pysymex.core.constants import Z3_FALSE
from pysymex.logger import get_logger

logger = get_logger(__name__)


def simplify_expr(expr: z3.ExprRef) -> z3.ExprRef:
    """Simplify one Z3 expression through the constraint simplification SSoT."""
    return z3.simplify(expr)


def simplify_bool_expr(expr: z3.BoolRef) -> z3.BoolRef:
    """Simplify one Boolean Z3 expression and preserve the BoolRef contract."""
    simplified = simplify_expr(expr)
    if not isinstance(simplified, z3.BoolRef):
        logger.warning("Z3 simplification returned non-boolean expression")
        raise TypeError("simplified Boolean expression did not produce a BoolRef")
    return simplified


def simplify_constraints(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Simplify a list of Z3 constraints.

    For small sets, applies z3.simplify per constraint.
    For larger sets (>50), uses Z3 tactic pipeline for deeper simplification.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Simplified list of constraints (possibly shorter).

    Notes:
        This function rewrites expressions; it does not classify a path as
        SAT, UNSAT, or UNKNOWN.
    """
    if not constraints:
        return []

    filtered: list[z3.BoolRef] = []
    for c in constraints:
        if z3.is_true(c):
            continue
        if z3.is_false(c):
            return [Z3_FALSE]
        simplified = simplify_bool_expr(c)
        if z3.is_true(simplified):
            continue
        if z3.is_false(simplified):
            return [Z3_FALSE]
        filtered.append(simplified)

    if not filtered:
        return []

    if len(filtered) <= 50:
        return filtered

    return tactic_simplify(filtered)


def tactic_simplify(constraints: list[z3.BoolRef]) -> list[z3.BoolRef]:
    """Use Z3 tactics for deeper simplification of large constraint sets.

    Applies: simplify -> propagate-values -> ctx-solver-simplify with 200ms timeout.

    Args:
        constraints: List of Z3 boolean constraints.

    Returns:
        Simplified constraints, or original if tactic fails or times out.

    Notes:
        Returning the original constraints on tactic failure preserves input
        for later solver classification; no outcome is claimed here.
    """
    try:
        goal = z3.Goal()
        goal.add(*constraints)
        tactic = z3.TryFor(z3.Then("simplify", "propagate-values", "ctx-solver-simplify"), 200)
        result = tactic(goal)
        if len(result) == 1:
            subgoal = result[0]
            simplified = list(subgoal)
            if simplified:
                return simplified

            return []

        return constraints
    except z3.Z3Exception:
        logger.warning("Z3 tactic simplification failed; using original constraints", exc_info=True)
        return constraints
