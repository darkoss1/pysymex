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

"""Path-feasibility helpers shared by all detector pure functions.

Provides :func:`get_model_if_satisfiable_result` which is the common pattern:
check SAT, obtain structured model evidence, and optionally use cheap witness
fast paths to avoid timeouts on hard constraints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

import pysymex._internal.analysis.evidence.cache as _evidence_cache
import pysymex._internal.analysis.evidence.result as _feasibility_result
import pysymex._internal.analysis.evidence.solvers as _evidence_solvers
from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.floats import (
    extract_zero_float_witness,
    zero_float_witness_model,
)
from pysymex._internal.analysis.evidence.integers import (
    extract_integer_witness,
    integer_witness_model,
)
from pysymex._internal.analysis.evidence.string.retry import (
    has_string_retry_context,
)
from pysymex._internal.analysis.evidence.strings import (
    extract_string_integer_witness,
    string_integer_witness_model,
)
from pysymex._internal.core.solver.constraints.literals import exact_bool_literal
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.queries import (
    get_model,
    get_model_result,
)
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.solver.query.planner import symbolic_query
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import GetModelFn, IsSatFn

logger = get_logger(__name__)

_MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS = 50


def detector_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return any supported concrete detector witness for *constraints*.

    This combines the detector witness pre-checks used before general Z3
    solving so cache misses do not traverse the same formula once per witness
    family. Each returned model is still accepted only after concrete
    substitution simplifies the complete formula to ``True``.
    """
    if not _evidence_solvers.evidence_budget_available():
        return None
    try:
        query = symbolic_query(constraints)
        formula = query.simplified_conjunction()
        if formula is None or z3.is_false(formula):
            return None
        constants = _evidence_cache.witness_constants(formula)
        if constants.fp_variables:
            witness = extract_zero_float_witness(formula, constants.fp_variables)
            if witness is not None:
                return witness
        if constants.string_variables:
            witness = extract_string_integer_witness(
                formula,
                string_variables=constants.string_variables,
                integer_variables=constants.integer_variables,
                bool_variables=constants.bool_variables,
            )
            if witness is not None:
                return witness
        if constants.integer_variables or constants.bool_variables:
            witness = extract_integer_witness(
                formula,
                constants.integer_variables,
                bool_variables=constants.bool_variables,
            )
            if witness is not None:
                return witness
        return None
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Detector witness feasibility check failed; treating as inconclusive")
    return None


def hard_theory_witness_model(
    constraints: list[z3.BoolRef],
    *,
    include_bitvector: bool = True,
) -> z3.ModelRef | None:
    """Return a verified witness only for formulas likely to stress the solver."""
    if not _evidence_solvers.evidence_budget_available():
        return None
    query = symbolic_query(constraints)
    if query.exact_literal_result() is False:
        return None
    if not query.contains_hard_witness_theory(include_bitvector=include_bitvector):
        return None
    return detector_witness_model(constraints)


def get_model_if_satisfiable_result(
    constraints: list[z3.BoolRef],
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn = get_model,
    *,
    allow_witness_model: bool = True,
) -> _feasibility_result.FeasibilityModelResult:
    """Return structured model evidence for satisfiable detector constraints.

    Args:
        constraints: The constraint list to check.
        is_satisfiable_fn: SAT oracle callback.
        get_model_fn: Model-extraction callback.

    Returns:
        Structured model evidence. ``SAT`` always contains a model; callback
        failures, model callback failures, and SAT-without-model results are
        ``INCONCLUSIVE``.

    """
    try:
        is_satisfiable = is_satisfiable_fn(constraints)
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Detector SAT callback failed; treating feasibility as inconclusive")
        return _feasibility_result.FeasibilityModelResult.inconclusive("sat_callback_failed")

    if not is_satisfiable:
        if allow_witness_model:
            witness = hard_theory_witness_model(constraints, include_bitvector=False)
            if witness is not None:
                return _feasibility_result.FeasibilityModelResult.sat(witness)
        return _feasibility_result.FeasibilityModelResult.no_sat_evidence(
            "sat_callback_returned_false",
        )
    if _constraints_are_exactly_true(constraints):
        return _feasibility_result.FeasibilityModelResult.sat({})
    if allow_witness_model:
        witness = zero_float_witness_model(constraints)
        if witness is not None:
            return _feasibility_result.FeasibilityModelResult.sat(witness)
    if get_model_fn is get_model:
        model = _model_from_sat_oracle(is_satisfiable_fn, constraints)
        if model is not None:
            return _feasibility_result.FeasibilityModelResult.sat(model)
    if get_model_fn is get_model and SolverContext.active.get() is not None:
        result = _model_result_to_feasibility(get_model_result(constraints))
        if result.is_inconclusive and allow_witness_model:
            witness = hard_theory_witness_model(constraints)
            if witness is not None:
                return _feasibility_result.FeasibilityModelResult.sat(witness)
            detached_result = _model_result_to_feasibility(
                _detached_model_result_for_active_solver(constraints),
            )
            if not detached_result.is_inconclusive:
                return detached_result
        return result
    if allow_witness_model:
        witness = integer_witness_model(constraints)
        if witness is not None:
            return _feasibility_result.FeasibilityModelResult.sat(witness)
        witness = string_integer_witness_model(constraints)
        if witness is not None:
            return _feasibility_result.FeasibilityModelResult.sat(witness)
    if get_model_fn is get_model:
        result = _model_result_to_feasibility(get_model_result(constraints))
        if result.is_inconclusive and allow_witness_model:
            witness = hard_theory_witness_model(constraints)
            if witness is not None:
                return _feasibility_result.FeasibilityModelResult.sat(witness)
        return result
    try:
        model = get_model_fn(constraints)
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Detector model callback failed; treating feasibility as inconclusive")
        return _feasibility_result.FeasibilityModelResult.inconclusive("model_callback_failed")
    if model is None:
        logger.debug(
            "Detector SAT evidence produced no model; treating feasibility as inconclusive",
        )
        return _feasibility_result.FeasibilityModelResult.inconclusive("sat_without_model")
    return _feasibility_result.FeasibilityModelResult.sat(model)


def _model_from_sat_oracle(
    is_satisfiable_fn: IsSatFn,
    constraints: list[z3.BoolRef],
) -> z3.ModelRef | None:
    """Return model evidence from a richer SAT oracle when one is available."""
    get_model_method = getattr(is_satisfiable_fn, "get_model", None)
    if not callable(get_model_method):
        return None
    try:
        model = get_model_method(constraints)
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Detector SAT oracle model extraction failed; treating as inconclusive")
        return None
    if isinstance(model, z3.ModelRef):
        return model
    return None


def _model_result_to_feasibility(
    result: SolverResult,
) -> _feasibility_result.FeasibilityModelResult:
    """Convert core structured model evidence to detector feasibility evidence."""
    if result.is_sat:
        if result.model is not None:
            return _feasibility_result.FeasibilityModelResult.sat(result.model)
        logger.debug("Detector SAT model result did not include a model")
        return _feasibility_result.FeasibilityModelResult.inconclusive("sat_without_model")
    if result.is_unsat:
        return _feasibility_result.FeasibilityModelResult.no_sat_evidence("model_result_unsat")
    if result.is_unknown:
        return _feasibility_result.FeasibilityModelResult.inconclusive("model_result_unknown")
    logger.debug("Detector model result was not a recognized solver outcome")
    return _feasibility_result.FeasibilityModelResult.inconclusive("model_result_invalid")


def _detached_model_result_for_active_solver(constraints: list[z3.BoolRef]) -> SolverResult:
    """Return model evidence from a fresh solver when the active context is inconclusive."""
    if not has_string_retry_context(constraints):
        return SolverResult.unknown()
    solver = SolverContext.active.get()
    if solver is None:
        return SolverResult.unknown()
    timeout_ms = _active_solver_retry_timeout_ms(solver)
    if timeout_ms is None:
        return SolverResult.unknown()
    try:
        return IncrementalSolver(timeout_ms=timeout_ms, use_cache=False).check_sat_cached(
            constraints,
        )
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Detached detector model retry failed; treating as inconclusive")
    return SolverResult.unknown()


def _active_solver_retry_timeout_ms(solver: object) -> int | None:
    """Return a bounded timeout for detached detector model extraction."""
    effective_timeout = getattr(solver, "_effective_timeout_ms", None)
    if not callable(effective_timeout):
        return None
    try:
        timeout_ms = effective_timeout()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Could not resolve active solver timeout for detached model retry")
        return None
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        return None
    return min(timeout_ms, _MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS)


def _constraints_are_exactly_true(constraints: list[z3.BoolRef]) -> bool:
    """Return whether every detector constraint is locally proved true."""
    return all(exact_bool_literal(constraint) is True for constraint in constraints)
