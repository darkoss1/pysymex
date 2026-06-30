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

"""Detector SAT-query decision publication."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.query.storage import store_detector_query_cache_entry
from pysymex._internal.execution.detectors.telemetry import (
    DetectorQueryContext,
    emit_detector_query_event,
)
from pysymex._internal.execution.detectors.unknown import record_detector_query_unknown

if TYPE_CHECKING:
    import z3

    from pysymex._internal.execution.detectors.query.cache.decisions import DetectorQueryDecision
    from pysymex._internal.execution.detectors.records import DetectorQueryCacheEntry
    from pysymex._internal.execution.session.state.core import ExecutionSession


def publish_detector_query_decision(
    *,
    session: ExecutionSession,
    cache_key: int,
    cached_entries: list[DetectorQueryCacheEntry] | None,
    constraints: list[z3.BoolRef],
    raw_constraints_count: int,
    inconclusive_prefix_len: int | None,
    query_context: DetectorQueryContext | None,
    decision: DetectorQueryDecision,
) -> None:
    """Store definitive answers, emit telemetry, and record inconclusive query state."""
    if decision.cacheable:
        store_detector_query_cache_entry(
            session=session,
            cache_key=cache_key,
            cached_entries=cached_entries,
            constraints=constraints,
            is_sat=decision.result,
        )
    emit_detector_query_event(
        session=session,
        query_context=query_context,
        raw_constraints_count=raw_constraints_count,
        constraints_count=len(constraints),
        inconclusive_prefix_len=inconclusive_prefix_len,
        result=decision.result,
        result_source=decision.result_source,
        cache_hit=False,
        witness_used=decision.witness_used,
        constraints=constraints,
    )
    if decision.unknown_reason is not None:
        record_detector_query_unknown(
            session=session,
            constraints_count=len(constraints),
            reason=decision.unknown_reason,
        )
    elif decision.result_source == "solver_unknown":
        record_detector_query_unknown(
            session=session,
            constraints_count=len(constraints),
        )
