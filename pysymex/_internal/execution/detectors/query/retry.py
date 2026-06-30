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

"""Model-backed retry path for detector SAT queries after solver UNKNOWN."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import SolverProtocol

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS = 50


def model_backed_detector_query(
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
) -> SolverResult:
    """Retry a detector query through the model-producing solver path.

    The first detector query uses the cheaper result-only path. If that path is
    inconclusive, this retry may still establish a definitive SAT or UNSAT result
    without weakening UNKNOWN: exceptions and solver UNKNOWN remain inconclusive
    and are handled by the caller.
    """
    try:
        result = solver.check_sat_cached(constraints)
    except _SOLVER_QUERY_ERRORS:
        logger.debug("Model-backed detector query retry failed", exc_info=True)
    else:
        if not result.is_unknown:
            return result
    return _detached_model_backed_detector_query(solver, constraints)


def _detached_model_backed_detector_query(
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
) -> SolverResult:
    """Retry with a fresh solver when the active incremental context remains UNKNOWN."""
    if not _has_string_retry_context(constraints):
        return SolverResult.unknown()
    timeout_ms = _effective_retry_timeout_ms(solver)
    if timeout_ms is None:
        return SolverResult.unknown()
    try:
        return IncrementalSolver(timeout_ms=timeout_ms, use_cache=False).check_sat_cached(
            constraints,
        )
    except _SOLVER_QUERY_ERRORS:
        logger.debug("Detached model-backed detector query retry failed", exc_info=True)
    return SolverResult.unknown()


def _effective_retry_timeout_ms(solver: SolverProtocol) -> int | None:
    """Return a bounded timeout for a detached detector retry, if available."""
    effective_timeout = getattr(solver, "_effective_timeout_ms", None)
    if not callable(effective_timeout):
        return None
    try:
        timeout_ms = effective_timeout()
    except _SOLVER_QUERY_ERRORS:
        logger.debug("Could not resolve effective solver timeout for detector retry")
        return None
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        return None
    return min(timeout_ms, _MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS)


def _has_string_retry_context(constraints: list[z3.BoolRef]) -> bool:
    """Return whether detached retry is justified by string-model-derived slots."""
    pending: list[z3.ExprRef] = list(constraints)
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_id = expression.get_id()
        if expression_id in visited:
            continue
        visited.add(expression_id)
        try:
            if expression.decl().kind() == z3.Z3_OP_UNINTERPRETED and _retry_name_matches(
                expression.decl().name(),
            ):
                return True
            pending.extend(expression.children())
        except _SOLVER_QUERY_ERRORS:
            logger.debug("Detached retry context probe failed", exc_info=True)
            return False
    return False


def _retry_name_matches(name: str) -> bool:
    """Return whether a Z3 symbol name belongs to string-derived model precision."""
    if "count" in name:
        return True
    return name.startswith(
        (
            "bin_",
            "find_",
            "rfind_",
            "index_",
            "rindex_",
            "ord_",
        ),
    )
