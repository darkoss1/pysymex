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

"""Public detector SAT-query cache policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.query.cache.hits import cached_detector_query_decision
from pysymex._internal.execution.detectors.query.cache.prefix import inconclusive_prefix_decision
from pysymex._internal.execution.detectors.query.cache.publication import (
    publish_detector_query_decision,
)
from pysymex._internal.execution.detectors.query.cache.solver import solver_detector_query_decision
from pysymex._internal.execution.detectors.query.constraints import (
    canonicalize_detector_query_constraints,
    matching_known_sat_path_prefix_len,
    shared_inconclusive_prefix_len,
)
from pysymex._internal.execution.detectors.query.storage import detector_query_cache_key
from pysymex._internal.execution.detectors.telemetry import (
    DetectorQueryContext,
    emit_detector_query_event,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import z3

    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.typing.protocols import SolverProtocol

logger = get_logger(__name__)


def detector_query_is_sat(
    *,
    session: ExecutionSession,
    solver: SolverProtocol,
    constraints: list[z3.BoolRef],
    inconclusive_path_prefix: tuple[z3.BoolRef, ...] | None = None,
    known_sat_path_prefix: tuple[z3.BoolRef, ...] | None = None,
    query_context: DetectorQueryContext | None = None,
) -> bool:
    """Answer SAT for detector queries with structural-hash caching.

    Caches only definitive SAT/UNSAT answers. Solver UNKNOWN records the
    detector-owned fallback event and remains uncached so later definitive
    checks can still run.
    """
    raw_constraints_count = len(constraints)
    normalized_constraints = canonicalize_detector_query_constraints(constraints)
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
    cached_decision = cached_detector_query_decision(
        session=session,
        cache_key=cache_key,
        cached_entries=cached_entries,
        constraints=constraints,
        raw_constraints_count=raw_constraints_count,
        query_context=query_context,
    )
    if cached_decision is not None:
        return cached_decision.result

    session.detector_query_cache_misses += 1
    if logger.state.trace_enabled:
        logger.trace("detector query cache miss constraints=%d", len(constraints))

    inconclusive_prefix_len = shared_inconclusive_prefix_len(
        constraints,
        inconclusive_path_prefix,
    )
    known_sat_prefix_len = matching_known_sat_path_prefix_len(
        constraints,
        known_sat_path_prefix,
    )
    decision = inconclusive_prefix_decision(
        constraints=constraints,
        inconclusive_prefix_len=inconclusive_prefix_len,
    )
    if decision is None:
        decision = solver_detector_query_decision(
            solver,
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )

    publish_detector_query_decision(
        session=session,
        cache_key=cache_key,
        cached_entries=cached_entries,
        constraints=constraints,
        raw_constraints_count=raw_constraints_count,
        inconclusive_prefix_len=inconclusive_prefix_len,
        query_context=query_context,
        decision=decision,
    )
    return decision.result
