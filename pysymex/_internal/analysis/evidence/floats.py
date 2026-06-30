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

"""Floating-point witness probes for detector feasibility evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

import pysymex._internal.analysis.evidence.solvers as _evidence_solvers
from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.solvers import create_evidence_solver
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.query.planner import symbolic_query
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = get_logger(__name__)


def zero_float_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a concrete ``+0.0`` witness when it proves the full constraint SAT.

    Fast path for IEEE-754 detector formulas that may time out in the
    general solver: substitutes every uninterpreted floating-point
    constant with ``+0.0`` and checks whether the simplified formula is
    ``True``. Returns a tiny witness model if so, ``None`` otherwise.

    Args:
        constraints: Z3 boolean constraints to probe.

    Returns:
        A minimal :class:`z3.ModelRef` assigning ``+0.0`` to all FP
        constants, or ``None`` if the fast path does not apply.

    """
    if not _evidence_solvers.evidence_budget_available():
        return None
    try:
        query = symbolic_query(constraints)
        formula = query.conjunction()
        return extract_zero_float_witness(
            formula,
            floating_point_constants(formula),
        )
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Float witness feasibility check failed; treating as inconclusive")
        return None


def floating_point_constants(formula: z3.ExprRef) -> list[z3.FPRef]:
    """Collect uninterpreted floating-point constant leaves from *formula*.

    Uses a non-recursive iterative traversal to avoid stack depth issues on
    large formulas.
    """
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants: list[z3.FPRef] = []
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if isinstance(expression, z3.FPRef) and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            constants.append(expression)
            continue
        pending.extend(expression.children())
    return constants


def extract_zero_float_witness(
    formula: z3.ExprRef,
    variables: Sequence[z3.FPRef],
) -> z3.ModelRef | None:
    """Return a ``+0.0`` witness when substitution proves *formula* SAT."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    substitutions = [(variable, z3.FPVal(0.0, variable.sort())) for variable in variables]
    if not substitutions or not z3.is_true(simplify_expr(z3.substitute(formula, *substitutions))):
        return None
    witness_solver = create_evidence_solver()
    if witness_solver is None:
        return None
    witness_solver.add(*(variable == value for variable, value in substitutions))
    if witness_solver.check() != z3.sat:
        return None
    return witness_solver.model()
