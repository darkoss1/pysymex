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

"""Detector SAT-query cache policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.feasibility import (
    detector_witness_model,
    zero_float_witness_model,
)
from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.execution.detectors import record_detector_query_unknown
from pysymex.execution.detectors.query.storage import (
    collect_detector_query_stats,
    detector_query_cache_key,
    DETECTOR_QUERY_CACHE_MAX_ENTRIES,
    same_detector_query_constraints,
    store_detector_query_cache_entry,
)
from pysymex.execution.detectors.telemetry import (
    DetectorQueryContext,
    DetectorQueryResultSource,
    emit_detector_query_event,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.execution.session.state import ExecutionSession
    from pysymex.typing import SolverProtocol

__all__ = [
    "DETECTOR_QUERY_CACHE_MAX_ENTRIES",
    "collect_detector_query_stats",
    "detector_query_is_sat",
]

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS = 50


def detector_query_is_sat(
    *,
    session: ExecutionSession,
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
    inconclusive_path_prefix: tuple[z3.BoolRef, ...] | None = None,
    query_context: DetectorQueryContext | None = None,
) -> bool:
    """Answer SAT for detector queries with structural-hash caching.

    Caches only definitive SAT/UNSAT answers. Solver UNKNOWN records the
    detector-owned fallback event and remains uncached so later definitive
    checks can still run.
    """
    raw_constraints_count = len(constraints)
    normalized_constraints = _normalize_detector_query_constraints(constraints)
    if isinstance(normalized_constraints, bool):
        emit_detector_query_event(
            session=session,
            query_context=query_context,
            raw_constraints_count=raw_constraints_count,
            constraints_count=0,
            inconclusive_prefix_len=None,
            result=normalized_constraints,
            result_source="literal_true" if normalized_constraints else "literal_false",
            cache_hit=False,
            witness_used=False,
        )
        return normalized_constraints
    constraints = normalized_constraints

    if not constraints:
        emit_detector_query_event(
            session=session,
            query_context=query_context,
            raw_constraints_count=raw_constraints_count,
            constraints_count=0,
            inconclusive_prefix_len=None,
            result=True,
            result_source="literal_true",
            cache_hit=False,
            witness_used=False,
        )
        return True

    cache_key = detector_query_cache_key(session, constraints)
    cached_entries = session.detector_query_cache.get(cache_key)
    if cached_entries is not None:
        for cached_entry in cached_entries:
            if same_detector_query_constraints(
                session,
                cached_entry.constraints,
                constraints,
            ):
                session.detector_query_cache_hits += 1
                session.detector_query_cache.move_to_end(cache_key)
                if logger.state.trace_enabled:
                    logger.trace(
                        "detector query cache hit constraints=%d result=%s",
                        len(constraints),
                        cached_entry.result,
                    )
                emit_detector_query_event(
                    session=session,
                    query_context=query_context,
                    raw_constraints_count=raw_constraints_count,
                    constraints_count=len(constraints),
                    inconclusive_prefix_len=None,
                    result=cached_entry.result,
                    result_source="cache_hit",
                    cache_hit=True,
                    witness_used=False,
                    constraints=constraints,
                )
                return cached_entry.result

    session.detector_query_cache_misses += 1
    if logger.state.trace_enabled:
        logger.trace("detector query cache miss constraints=%d", len(constraints))

    inconclusive_prefix_len = _matching_inconclusive_path_prefix_len(
        constraints,
        inconclusive_path_prefix,
    )
    if _should_try_inconclusive_prefix_witness(
        constraints=constraints,
        inconclusive_prefix_len=inconclusive_prefix_len,
    ):
        is_sat = detector_witness_model(constraints) is not None
        if is_sat:
            store_detector_query_cache_entry(
                session=session,
                cache_key=cache_key,
                cached_entries=cached_entries,
                constraints=constraints,
                is_sat=True,
            )
            emit_detector_query_event(
                session=session,
                query_context=query_context,
                raw_constraints_count=raw_constraints_count,
                constraints_count=len(constraints),
                inconclusive_prefix_len=inconclusive_prefix_len,
                result=True,
                result_source="inconclusive_prefix_witness",
                cache_hit=False,
                witness_used=True,
                constraints=constraints,
            )
            return True
        emit_detector_query_event(
            session=session,
            query_context=query_context,
            raw_constraints_count=raw_constraints_count,
            constraints_count=len(constraints),
            inconclusive_prefix_len=inconclusive_prefix_len,
            result=False,
            result_source="inconclusive_prefix_unknown",
            cache_hit=False,
            witness_used=False,
            constraints=constraints,
        )
        record_detector_query_unknown(
            session=session,
            constraints_count=len(constraints),
            reason=(
                "detector query extends an inconclusive path-feasibility "
                f"prefix with {len(constraints)} constraint(s)"
            ),
        )
        return False

    if inconclusive_prefix_len is not None and len(constraints) == inconclusive_prefix_len:
        is_sat = detector_witness_model(constraints) is not None
        if not is_sat:
            emit_detector_query_event(
                session=session,
                query_context=query_context,
                raw_constraints_count=raw_constraints_count,
                constraints_count=len(constraints),
                inconclusive_prefix_len=inconclusive_prefix_len,
                result=False,
                result_source="inconclusive_prefix_unknown",
                cache_hit=False,
                witness_used=False,
                constraints=constraints,
            )
            record_detector_query_unknown(
                session=session,
                constraints_count=len(constraints),
                reason=(
                    "detector query extends an inconclusive path-feasibility "
                    f"prefix with {len(constraints)} constraint(s)"
                ),
            )
            return False
        result_source: DetectorQueryResultSource = "inconclusive_prefix_witness"
        witness_used = True
    else:
        is_sat = zero_float_witness_model(constraints) is not None
        if is_sat:
            result_source = "zero_float_witness"
            witness_used = True
        else:
            witness_used = False
            result = solver.check_sat_result(constraints, known_sat_prefix_len=None)
            if result.is_sat or result.is_unsat:
                is_sat = result.is_sat
                result_source = "solver_sat" if result.is_sat else "solver_unsat"
            else:
                witness_used = True
                is_sat = detector_witness_model(constraints) is not None
                if is_sat:
                    result_source = "witness_after_solver_unknown"
                else:
                    model_result = _model_backed_detector_query(solver, constraints)
                    if model_result.is_sat or model_result.is_unsat:
                        is_sat = model_result.is_sat
                        result_source = "solver_sat" if model_result.is_sat else "solver_unsat"
                        witness_used = False
                    else:
                        emit_detector_query_event(
                            session=session,
                            query_context=query_context,
                            raw_constraints_count=raw_constraints_count,
                            constraints_count=len(constraints),
                            inconclusive_prefix_len=inconclusive_prefix_len,
                            result=False,
                            result_source="solver_unknown",
                            cache_hit=False,
                            witness_used=False,
                            constraints=constraints,
                        )
                        record_detector_query_unknown(
                            session=session,
                            constraints_count=len(constraints),
                        )
                        return False

    store_detector_query_cache_entry(
        session=session,
        cache_key=cache_key,
        cached_entries=cached_entries,
        constraints=constraints,
        is_sat=is_sat,
    )
    emit_detector_query_event(
        session=session,
        query_context=query_context,
        raw_constraints_count=raw_constraints_count,
        constraints_count=len(constraints),
        inconclusive_prefix_len=inconclusive_prefix_len,
        result=is_sat,
        result_source=result_source,
        cache_hit=False,
        witness_used=witness_used,
        constraints=constraints,
    )
    return is_sat


def _should_try_inconclusive_prefix_witness(
    *,
    constraints: list[z3.BoolRef],
    inconclusive_prefix_len: int | None,
) -> bool:
    """Return whether a verified witness should precede a repeated hard solver query."""
    return inconclusive_prefix_len is not None and len(constraints) > inconclusive_prefix_len


def _matching_inconclusive_path_prefix_len(
    constraints: list[z3.BoolRef],
    inconclusive_path_prefix: tuple[z3.BoolRef, ...] | None,
) -> int | None:
    """Return the non-trivial inconclusive-prefix length matched by a query."""
    if inconclusive_path_prefix is None:
        return None
    expected_prefix = tuple(
        constraint
        for constraint in inconclusive_path_prefix
        if exact_bool_literal(constraint) is not True
    )
    if not expected_prefix:
        return None
    prefix_len = len(expected_prefix)
    if len(constraints) < prefix_len:
        return None
    for expected, actual in zip(expected_prefix, constraints[:prefix_len], strict=True):
        if expected is actual:
            continue
        if not z3.eq(expected, actual):
            return None
    return prefix_len


def _normalize_detector_query_constraints(constraints: list[z3.BoolRef]) -> bool | list[z3.BoolRef]:
    """Drop literal truths and short-circuit literal falsehoods in detector queries."""
    if not constraints:
        return True

    nontrivial_constraints_reversed: list[z3.BoolRef] = []
    for constraint in reversed(constraints):
        literal = exact_bool_literal(constraint)
        if literal is False:
            return False
        if literal is not True:
            nontrivial_constraints_reversed.append(constraint)
    if not nontrivial_constraints_reversed:
        return True
    nontrivial_constraints_reversed.reverse()
    nontrivial_constraints = nontrivial_constraints_reversed
    return nontrivial_constraints


def _model_backed_detector_query(
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
) -> SolverResult:
    """Retry a detector query through the model-producing solver path.

    The first detector query uses the cheaper result-only path.  If that
    path is inconclusive, this retry may still establish a definitive SAT or
    UNSAT result without weakening UNKNOWN: exceptions and solver UNKNOWN
    remain inconclusive and are handled by the caller.
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
    if not _constraints_include_string_model_retry_context(constraints):
        return SolverResult.unknown()
    timeout_ms = _effective_retry_timeout_ms(solver)
    if timeout_ms is None:
        return SolverResult.unknown()
    try:
        return IncrementalSolver(timeout_ms=timeout_ms, use_cache=False).check_sat_cached(
            constraints
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


def _constraints_include_string_model_retry_context(constraints: list[z3.BoolRef]) -> bool:
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
                expression.decl().name()
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
        )
    )
