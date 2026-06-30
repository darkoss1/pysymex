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

"""Exact UNSAT-subset cache methods for incremental solver queries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.engine.cache.unsat.subset.core import (
    constraint_hash_counts,
    constraint_hash_counts_contained,
    constraint_hash_counts_from_buckets,
    unsat_subset_matches,
)
from pysymex._internal.core.solver.engine.caches import UnsatSubsetCacheEntry
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.solver.engine.types import SolverMixinContract
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections import deque

    import z3

    from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher

logger = get_logger(__name__)


class SolverUnsatSubsetCacheMixin(SolverMixinContract):
    """Store and reuse exact UNSAT subsets without changing solver uncertainty semantics."""

    if TYPE_CHECKING:
        _cache_hits: int
        _hasher: ConstraintHasher
        _unsat_subset_cache: deque[UnsatSubsetCacheEntry]
        _use_cache: bool

    def _lookup_unsat_subset_cache(self, constraints: list[z3.BoolRef]) -> SolverResult | None:
        """Return UNSAT when a cached UNSAT conjunction is an exact subset."""
        if not self._use_cache or not self._unsat_subset_cache or not constraints:
            return None

        query_buckets: dict[int, list[z3.BoolRef]] | None = None
        query_hash_counts: dict[int, int] | None = None
        for entry in reversed(self._unsat_subset_cache):
            if len(entry.constraints) > len(constraints):
                continue
            if query_buckets is None:
                query_buckets = self._constraint_hash_buckets(constraints)
                query_hash_counts = constraint_hash_counts_from_buckets(query_buckets)
            if query_hash_counts is None:
                return None
            if not constraint_hash_counts_contained(
                subset_counts=entry.constraint_hash_counts,
                query_counts=query_hash_counts,
            ):
                continue
            if unsat_subset_matches(
                entry.constraints,
                entry.constraint_hashes,
                query_buckets,
            ):
                self._cache_hits += 1
                if logger.state.trace_enabled:
                    logger.trace(
                        "solver UNSAT subset cache hit constraints=%d subset=%d",
                        len(constraints),
                        len(entry.constraints),
                    )
                return SolverResult.unsat()
        return None

    def _store_unsat_subset_cache(
        self,
        constraints: list[z3.BoolRef],
        result: SolverResult,
    ) -> None:
        """Retain an exact UNSAT conjunction for later superset checks."""
        if not self._use_cache or not result.is_unsat or not constraints:
            return
        constraint_hashes = tuple(self._hasher.hash_expr(constraint) for constraint in constraints)
        self._unsat_subset_cache.append(
            UnsatSubsetCacheEntry(
                constraints=tuple(constraints),
                constraint_hashes=constraint_hashes,
                constraint_hash_counts=constraint_hash_counts(constraint_hashes),
            ),
        )

    def _constraint_hash_buckets(
        self,
        constraints: list[z3.BoolRef],
    ) -> dict[int, list[z3.BoolRef]]:
        """Group query constraints by structural hash for exact subset validation."""
        buckets: dict[int, list[z3.BoolRef]] = {}
        for constraint in constraints:
            buckets.setdefault(self._hasher.hash_expr(constraint), []).append(constraint)
        return buckets
