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

"""Scope-aware cache-key and cache-entry helpers for IncrementalSolver."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable
from pysymex.logger import get_logger
from typing import TYPE_CHECKING

import z3

from pysymex.core.solver.constraints.hashing import ConstraintHasher, structural_hash
from pysymex.core.solver.engine.caches import (
    CACHE_CONTEXT_MASK,
    CheckCacheEntry,
    UnsatSubsetCacheEntry,
)
from pysymex.core.solver.engine.check_cache_methods import SolverCheckCacheMixin
from pysymex.core.solver.engine.types import SolverMixinContract
from pysymex.core.solver.engine.constraints import has_to_z3
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.engine.unsat_subset_cache import (
    constraint_hash_counts,
    constraint_hash_counts_contained,
    constraint_hash_counts_from_buckets,
    unsat_subset_matches,
)
from pysymex.core.solver.independence.optimizer import ConstraintIndependenceOptimizer
from pysymex.core.z3_utils import safe_z3_eq

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)


class SolverCacheMixin(SolverCheckCacheMixin, SolverMixinContract):
    """Synchronize incremental paths and cache structured SAT query results.

    Cache lookups validate structural discriminators after hash prefilters.
    ``UNKNOWN`` results are not stored as reusable SAT/UNSAT evidence.
    """

    if TYPE_CHECKING:
        active_path: list[z3.BoolRef]
        cache: OrderedDict[tuple[int, tuple[str, ...]], SolverResult]
        _cache_context_stack: list[int]
        _cache_hits: int
        _cache_index: dict[int, set[tuple[str, ...]]]
        _cache_size: int
        _check_cache: OrderedDict[int, list[CheckCacheEntry]]
        _constraint_fingerprint_cache: OrderedDict[int, list[tuple[z3.ExprRef, str]]]
        _constraint_fingerprint_cache_max_size: int
        _constraint_scope_stack: list[list[z3.BoolRef]]
        _hasher: ConstraintHasher
        _optimizer: ConstraintIndependenceOptimizer
        pending_constraint_scope_stack: list[list[z3.BoolRef]]
        _unsat_subset_cache: deque[UnsatSubsetCacheEntry]
        _use_cache: bool

        def add(self, *constraints: z3.BoolRef) -> None:
            """Assert normalized constraints in the owning solver."""
            ...

        def expr_equal(self, a: z3.BoolRef, b: z3.BoolRef) -> bool:
            """Return structural equality for synchronized path expressions."""
            ...

        def pop(self) -> None:
            """Pop one owning solver scope."""
            ...

        def push(self) -> None:
            """Push one owning solver scope."""
            ...

    def _common_prefix_len(self, target: list[z3.BoolRef]) -> int:
        """Return common prefix length between synchronized and target paths."""
        limit = min(len(self.active_path), len(target))
        idx = 0
        while idx < limit and self.expr_equal(self.active_path[idx], target[idx]):
            idx += 1
        return idx

    def _sync_path(self, target_prefix: list[z3.BoolRef]) -> None:
        """Synchronize solver ambient context to *target_prefix* in O(delta) scopes.

        Each prefix element is represented by one push-scope frame, so we can
        pop exactly the divergent suffix and push only the missing delta.
        """
        lcp = self._common_prefix_len(target_prefix)

        while len(self.active_path) > lcp:
            self.pop()
            self.active_path.pop()

        for constraint in target_prefix[lcp:]:
            self.push()
            try:
                self.add(constraint)
            except _SOLVER_QUERY_ERRORS:
                try:
                    self.pop()
                except _SOLVER_QUERY_ERRORS:
                    logger.debug(
                        "Solver scope cleanup failed after sync-path add failure",
                        exc_info=True,
                    )
                    self.reset()
                raise
            self.active_path.append(constraint)

    @staticmethod
    def _mix_cache_context(seed: int, value: int) -> int:
        """Combine cache context values deterministically."""
        return ((seed * 1000003) ^ (value + 0x9E3779B97F4A7C15)) & CACHE_CONTEXT_MASK

    def _current_cache_context(self) -> int:
        """Return the cache context for the current ambient solver state."""
        return self._cache_context_stack[-1]

    def _pending_assumptions(self) -> tuple[z3.BoolRef, ...]:
        """Return lazily added constraints that should participate in checks."""
        assumptions: list[z3.BoolRef] = []
        for scope_constraints in self.pending_constraint_scope_stack:
            assumptions.extend(scope_constraints)
        return tuple(assumptions)

    def _flush_pending_constraints(self) -> None:
        """Clear tracking for constraints already asserted by :meth:`add`."""
        for pending in self.pending_constraint_scope_stack:
            pending.clear()

    def _make_cache_key(self, constraints: list[z3.BoolRef]) -> int:
        """Create a scope-aware cache key for a constraint set."""
        return self._mix_cache_context(
            self._current_cache_context(), structural_hash(constraints, self._hasher)
        )

    def _make_cache_key_for_constraints(
        self,
        constraints_obj: Iterable[z3.BoolRef],
        constraints: list[z3.BoolRef],
    ) -> int:
        """Create a scope-aware cache key with optional O(1) chain hashing."""
        hash_value_getter = getattr(constraints_obj, "hash_value", None)
        if callable(hash_value_getter):
            try:
                hv = hash_value_getter()
            except (AttributeError, TypeError, RuntimeError) as exc:
                logger.debug("Failed to get hash value from constraint chain: %s", exc)
                hv = None
            if isinstance(hv, int):
                return self._mix_cache_context(self._current_cache_context(), hv)
        return self._make_cache_key(constraints)

    def _constraint_fingerprint(self, constraint: z3.ExprRef) -> str:
        """Stable expression fingerprint used to isolate primary hash collisions."""
        if has_to_z3(constraint):
            constraint = constraint.to_z3()
        key = constraint.get_id()
        cached_entries = self._constraint_fingerprint_cache.get(key)
        if cached_entries is not None:
            for cached_constraint, cached_fingerprint in cached_entries:
                if cached_constraint is constraint or safe_z3_eq(cached_constraint, constraint):
                    self._constraint_fingerprint_cache.move_to_end(key)
                    return cached_fingerprint

        try:
            sexpr = constraint.sexpr()
        except _SOLVER_QUERY_ERRORS:
            sexpr = repr(constraint)
        sort = constraint.sort() if hasattr(constraint, "sort") else "<unknown>"
        fingerprint = f"{constraint.hash()}:{sort}:{sexpr}"
        if cached_entries is None:
            self._constraint_fingerprint_cache[key] = [(constraint, fingerprint)]
        else:
            cached_entries.append((constraint, fingerprint))
            self._constraint_fingerprint_cache.move_to_end(key)
        while len(self._constraint_fingerprint_cache) > self._constraint_fingerprint_cache_max_size:
            self._constraint_fingerprint_cache.popitem(last=False)
        return fingerprint

    def _constraints_discriminator(self, constraints: list[z3.BoolRef]) -> tuple[str, ...]:
        """Secondary discriminator to safely resolve potential structural hash collisions.

        While structural_hash is fast, it is theoretically possible for different
        expressions to share a hash. This discriminator uses stable expression
        fingerprints so distinct constraints do not share cached SAT results.
        """
        if not constraints:
            return ()
        return tuple(sorted(self._constraint_fingerprint(c) for c in constraints))

    def _constraints_discriminator_for_constraints(
        self,
        constraints_obj: Iterable[z3.BoolRef],
        constraints: list[z3.BoolRef],
    ) -> tuple[str, ...]:
        """Secondary discriminator for cache collision detection."""
        _ = constraints_obj
        return self._constraints_discriminator(constraints)

    def _slice_prefix_for_suffix(
        self, prefix: list[z3.BoolRef], query: Iterable[z3.BoolRef] | z3.BoolRef
    ) -> list[z3.BoolRef]:
        """Return the dependency-retained prefix selected by the optimizer."""
        import z3

        q_list = [query] if isinstance(query, z3.ExprRef) else list(query)
        if not q_list:
            return prefix

        self._optimizer.sync_registered_path(prefix)

        combined_query = z3.And(*q_list) if len(q_list) > 1 else q_list[0]

        sliced = self._optimizer.slice_for_query(prefix, combined_query)
        return sliced

    def _cache_lookup(self, primary: int, discriminator: tuple[str, ...]) -> SolverResult | None:
        """Lookup a cached result, verifying the secondary discriminator."""
        if not self._use_cache:
            return None
        bucket = self._cache_index.get(primary)
        if bucket is None:
            return None
        if discriminator not in bucket:
            if logger.state.debug_enabled:
                logger.debug("SAT cache collision detected")
            return None
        key = (primary, discriminator)
        result = self.cache.get(key)
        if result is None:
            return None
        self._cache_hits += 1
        self.cache.move_to_end(key)
        if logger.state.trace_enabled:
            logger.trace(
                "solver SAT cache hit primary=%d constraints=%d", primary, len(discriminator)
            )
        return result

    def _cache_store(
        self, primary: int, discriminator: tuple[str, ...], result: SolverResult
    ) -> None:
        """Store a definitive cache entry, maintaining LRU order and index."""
        if not self._use_cache or result.is_unknown:
            return
        key = (primary, discriminator)
        if key in self.cache:
            self.cache[key] = result
            self.cache.move_to_end(key)
            self._cache_index.setdefault(primary, set()).add(discriminator)
            if logger.state.trace_enabled:
                logger.trace("solver SAT cache refreshed primary=%d", primary)
            return
        while len(self.cache) >= self._cache_size:
            old_key, _ = self.cache.popitem(last=False)
            old_primary, old_discriminator = old_key
            bucket = self._cache_index.get(old_primary)
            if bucket is not None:
                bucket.discard(old_discriminator)
                if not bucket:
                    del self._cache_index[old_primary]
        self.cache[key] = result
        self._cache_index.setdefault(primary, set()).add(discriminator)
        if logger.state.trace_enabled:
            logger.trace(
                "solver SAT cache stored primary=%d size=%d sat=%s unsat=%s unknown=%s",
                primary,
                len(self.cache),
                result.is_sat,
                result.is_unsat,
                result.is_unknown,
            )

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
        self, constraints: list[z3.BoolRef], result: SolverResult
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
            )
        )

    def _constraint_hash_buckets(
        self, constraints: list[z3.BoolRef]
    ) -> dict[int, list[z3.BoolRef]]:
        """Group query constraints by structural hash for exact subset validation."""
        buckets: dict[int, list[z3.BoolRef]] = {}
        for constraint in constraints:
            buckets.setdefault(self._hasher.hash_expr(constraint), []).append(constraint)
        return buckets
