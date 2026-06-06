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

"""Shared solver-query helpers for property proof modules."""

from __future__ import annotations

from collections.abc import Callable, Sequence
import time

import z3

from pysymex.analysis.static.properties.model_values import extract_model_values_result
from pysymex.analysis.static.properties.types import (
    ProofReason,
    ProofStatus,
    PropertyProof,
    PropertySpec,
)
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.logger import get_logger

ViolationConditionBuilder = Callable[[], Sequence[z3.BoolRef]]
logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)


def check_violation_query(
    solver: IncrementalSolver,
    spec: PropertySpec,
    variables: dict[str, z3.ExprRef],
    build_violation_conditions: ViolationConditionBuilder,
    constraints: Sequence[z3.BoolRef] | None = None,
    *,
    timeout_ms: int | None = None,
    classify_elapsed_timeout: bool = False,
) -> PropertyProof:
    """Check whether a property-violation query is satisfiable.

    A property is proven only when the encoded violation query is UNSAT. SAT
    disproves the property with a counterexample. Encoding failures, solver
    exceptions, Z3 ``unknown``, and elapsed timeouts are inconclusive.
    """
    start = time.perf_counter()
    solver.reset()
    try:
        query_constraints = list(constraints or ())
        query_constraints.extend(build_violation_conditions())
    except (z3.Z3Exception, OSError, RuntimeError, ValueError):
        solver.reset()
        elapsed = time.perf_counter() - start
        return PropertyProof(
            property=spec,
            status=ProofStatus.UNKNOWN,
            time_seconds=elapsed,
            reason=ProofReason.QUERY_EXCEPTION,
        )

    try:
        solver.add(*query_constraints)
        result = solver.check(need_model=True)
    except _SOLVER_QUERY_ERRORS:
        solver.reset()
        result = SolverResult.unknown()

    elapsed = time.perf_counter() - start
    return proof_from_solver_result(
        spec,
        variables,
        result,
        elapsed,
        timeout_ms=timeout_ms,
        classify_elapsed_timeout=classify_elapsed_timeout,
    )


def proof_from_solver_result(
    spec: PropertySpec,
    variables: dict[str, z3.ExprRef],
    result: SolverResult,
    elapsed: float,
    *,
    timeout_ms: int | None = None,
    classify_elapsed_timeout: bool = False,
) -> PropertyProof:
    """Convert a structured solver result into a property proof outcome."""
    if result.is_unsat:
        return PropertyProof(
            property=spec,
            status=ProofStatus.PROVEN,
            time_seconds=elapsed,
        )
    if result.is_sat:
        if result.model is None:
            logger.debug("Property violation query was SAT but no model was available")
            return PropertyProof(
                property=spec,
                status=ProofStatus.UNKNOWN,
                time_seconds=elapsed,
                reason=ProofReason.MISSING_COUNTEREXAMPLE_MODEL,
            )
        counterexample = extract_model_values_result(result.model, variables)
        if not counterexample.complete:
            logger.debug(
                "Property violation query model could not evaluate variables: %s",
                counterexample.failed_variables,
            )
            return PropertyProof(
                property=spec,
                status=ProofStatus.UNKNOWN,
                time_seconds=elapsed,
                counterexample=counterexample.values or None,
                reason=ProofReason.INCOMPLETE_COUNTEREXAMPLE,
            )
        return PropertyProof(
            property=spec,
            status=ProofStatus.DISPROVEN,
            counterexample=counterexample.values,
            time_seconds=elapsed,
        )

    status = ProofStatus.UNKNOWN
    reason = ProofReason.SOLVER_UNKNOWN
    if classify_elapsed_timeout and timeout_ms is not None and elapsed > timeout_ms / 1000:
        status = ProofStatus.TIMEOUT
        reason = ProofReason.ELAPSED_TIMEOUT
    return PropertyProof(property=spec, status=status, time_seconds=elapsed, reason=reason)
