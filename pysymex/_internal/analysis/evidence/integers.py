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

"""Integer witness probes for detector feasibility evidence."""

from __future__ import annotations

import z3

import pysymex._internal.analysis.evidence.cache as _evidence_cache
import pysymex._internal.analysis.evidence.solvers as _evidence_solvers
from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.integer.candidates import IntegerWitnesses
from pysymex._internal.analysis.evidence.integer.equalities import IntegerEqualities
from pysymex._internal.analysis.evidence.solvers import create_evidence_solver
from pysymex._internal.analysis.evidence.witness.models import substitution_model
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.solver.query.planner import symbolic_query
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)
_MAX_INTEGER_WITNESS_SEED_VARS = 6
_MAX_INTEGER_WITNESS_BOOL_VARS = 8


def integer_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a concrete small-integer witness when substitution proves SAT.

    This is a detector-only fallback for solver-unknown queries. It does not
    infer satisfiability from ``unknown``; it enumerates a small deterministic
    set of integer assignments and accepts one only when every supplied
    constraint simplifies to ``True`` after substitution.
    """
    if not _evidence_solvers.evidence_budget_available():
        return None
    try:
        query = symbolic_query(constraints)
        formula = query.simplified_conjunction()
        if formula is None or z3.is_false(formula):
            return None
        variables = integer_constants(formula, limit=_MAX_INTEGER_WITNESS_SEED_VARS + 1)
        return extract_integer_witness(formula, variables)
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Integer witness feasibility check failed; treating as inconclusive")
    return None


def integer_constants(
    formula: z3.ExprRef,
    *,
    limit: int | None = None,
) -> list[z3.ArithRef]:
    """Collect uninterpreted integer constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.ArithRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.ArithRef)
            and expression.sort().kind() == z3.Z3_INT_SORT
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            if limit is not None and len(constants_by_name) >= limit:
                return [constants_by_name[name] for name in sorted(constants_by_name)]
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def extract_integer_witness(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
    *,
    bool_variables: list[z3.BoolRef] | None = None,
) -> z3.ModelRef | None:
    """Return a verified integer witness for a simplified detector formula."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    if not variables or len(variables) > _MAX_INTEGER_WITNESS_SEED_VARS:
        return None
    direct_values = IntegerEqualities.assignment(formula, variables)
    if direct_values is not None:
        if bool_variables:
            direct_model = _verified_integer_bool_assignment_model(
                formula,
                integer_variables=variables,
                bool_variables=bool_variables,
                integer_values=direct_values,
            )
        else:
            direct_model = _verified_integer_assignment_model(formula, variables, direct_values)
        if direct_model is not None:
            return direct_model
    for values in IntegerWitnesses.assignments(len(variables), formula):
        if bool_variables:
            model = _verified_integer_bool_assignment_model(
                formula,
                integer_variables=variables,
                bool_variables=bool_variables,
                integer_values=values,
            )
        else:
            model = _verified_integer_assignment_model(formula, variables, values)
        if model is not None:
            return model
    return None


def _verified_integer_assignment_model(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
    values: tuple[int, ...],
) -> z3.ModelRef | None:
    if not _evidence_solvers.evidence_budget_available():
        return None
    substitutions = [
        (variable, ConstraintValues.int(value))
        for variable, value in zip(variables, values, strict=False)
    ]
    if not z3.is_true(simplify_expr(z3.substitute(formula, *substitutions))):
        return None
    return _assignment_model(variables, values)


def _verified_integer_bool_assignment_model(
    formula: z3.BoolRef,
    *,
    integer_variables: list[z3.ArithRef],
    bool_variables: list[z3.BoolRef],
    integer_values: tuple[int, ...],
) -> z3.ModelRef | None:
    """Verify an integer witness when only Boolean aggregate variables remain."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    integer_substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = [
        (variable, ConstraintValues.int(value))
        for variable, value in zip(integer_variables, integer_values, strict=True)
    ]
    simplified = simplify_expr(z3.substitute(formula, *integer_substitutions))
    if z3.is_true(simplified):
        return substitution_model(integer_substitutions)
    if z3.is_false(simplified) or _contains_non_bool_uninterpreted_constant(simplified):
        return None
    constants = _evidence_cache.collect_witness_constants(simplified)
    if (
        constants.integer_variables
        or constants.string_variables
        or constants.fp_variables
        or not constants.bool_variables
        or len(constants.bool_variables) > _MAX_INTEGER_WITNESS_BOOL_VARS
    ):
        return None
    bool_model = _boolean_residue_model(simplified, constants.bool_variables)
    if bool_model is None:
        return None
    return substitution_model([*integer_substitutions, *bool_model])


def _contains_non_bool_uninterpreted_constant(formula: z3.ExprRef) -> bool:
    """Return whether *formula* still has non-Boolean unassigned constants."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if expression.decl().kind() == z3.Z3_OP_UNINTERPRETED and not isinstance(
            expression,
            z3.BoolRef,
        ):
            return True
        pending.extend(expression.children())
    return False


def _boolean_residue_model(
    formula: z3.BoolRef,
    variables: list[z3.BoolRef],
) -> list[tuple[z3.ExprRef, z3.ExprRef]] | None:
    """Return Boolean assignments that satisfy a post-integer residue."""
    solver = create_evidence_solver()
    if solver is None:
        return None
    solver.add(formula)
    try:
        if solver.check() != z3.sat:
            return None
        model = solver.model()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Boolean residue witness check failed; treating as inconclusive")
        return None
    return [
        (variable, Z3_TRUE if z3.is_true(model.eval(variable, model_completion=True)) else Z3_FALSE)
        for variable in variables
    ]


def _assignment_model(
    variables: list[z3.ArithRef],
    values: tuple[int, ...],
) -> z3.ModelRef | None:
    substitutions = [
        (variable, ConstraintValues.int(value))
        for variable, value in zip(variables, values, strict=False)
    ]
    return substitution_model(
        substitutions,
        failure_message="Integer witness model extraction failed; treating as inconclusive",
    )
