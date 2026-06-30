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

"""Mechanical storage operations for detector SAT-query cache entries."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import z3

from pysymex._internal.core.solver.constraints.hashing import structural_hash
from pysymex._internal.execution.detectors.records import DetectorQueryCacheEntry

if TYPE_CHECKING:
    from pysymex._internal.execution.session.state.core import ExecutionSession

# Maximum structural-hash buckets retained for detector SAT-query caching.
DETECTOR_QUERY_CACHE_MAX_ENTRIES: Final = 4096


def collect_detector_query_stats(session: ExecutionSession) -> dict[str, object]:
    """Return hit/miss/size statistics for the detector SAT-query cache."""
    return {
        "cache_hits": session.detector_query_cache_hits,
        "cache_misses": session.detector_query_cache_misses,
        "cache_size": len(session.detector_query_cache),
        "cache_capacity": DETECTOR_QUERY_CACHE_MAX_ENTRIES,
    }


def detector_query_cache_key(session: ExecutionSession, constraints: list[z3.BoolRef]) -> int:
    """Return the structural hash used to bucket detector query-cache entries."""
    return structural_hash(constraints, session.detector_constraint_hasher)


def same_detector_query_constraints(
    session: ExecutionSession,
    left: tuple[z3.BoolRef, ...],
    right: list[z3.BoolRef],
) -> bool:
    """Return whether two constraint sequences are structurally equal for cache lookup."""
    if len(left) != len(right):
        return False
    for left_constraint, right_constraint in zip(left, right, strict=True):
        if session.detector_constraint_hasher.hash_expr(
            left_constraint,
        ) != session.detector_constraint_hasher.hash_expr(right_constraint):
            return False
        if not z3.eq(left_constraint, right_constraint):
            return False
    return True


def store_detector_query_cache_entry(
    *,
    session: ExecutionSession,
    cache_key: int,
    cached_entries: list[DetectorQueryCacheEntry] | None,
    constraints: list[z3.BoolRef],
    is_sat: bool,
) -> None:
    """Cache one definitive detector query answer."""
    entry = DetectorQueryCacheEntry(tuple(constraints), is_sat)
    if cached_entries is None:
        session.detector_query_cache[cache_key] = [entry]
    else:
        cached_entries.append(entry)
        session.detector_query_cache.move_to_end(cache_key)
    if len(session.detector_query_cache) > DETECTOR_QUERY_CACHE_MAX_ENTRIES:
        session.detector_query_cache.popitem(last=False)
