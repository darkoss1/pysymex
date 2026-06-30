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

"""Detector SAT-query cache-hit lookup and publication."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.query.cache.decisions import DetectorQueryDecision
from pysymex._internal.execution.detectors.query.storage import same_detector_query_constraints
from pysymex._internal.execution.detectors.telemetry import (
    DetectorQueryContext,
    emit_detector_query_event,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import z3

    from pysymex._internal.execution.detectors.records import DetectorQueryCacheEntry
    from pysymex._internal.execution.session.state.core import ExecutionSession

logger = get_logger(__name__)


def cached_detector_query_decision(
    *,
    session: ExecutionSession,
    cache_key: int,
    cached_entries: list[DetectorQueryCacheEntry] | None,
    constraints: list[z3.BoolRef],
    raw_constraints_count: int,
    query_context: DetectorQueryContext | None,
) -> DetectorQueryDecision | None:
    """Return and publish a cached detector-query answer when constraints match exactly."""
    if cached_entries is None:
        return None

    for cached_entry in cached_entries:
        if not same_detector_query_constraints(
            session,
            cached_entry.constraints,
            constraints,
        ):
            continue
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
        return DetectorQueryDecision(
            result=cached_entry.result,
            result_source="cache_hit",
            witness_used=False,
            cacheable=False,
        )
    return None
