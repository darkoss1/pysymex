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

from collections import OrderedDict
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.cache.control import register_process_cache_clearer
from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher, structural_hash
from pysymex._internal.core.solver.engine.cache.check.methods import SolverCheckCacheMixin
from pysymex._internal.core.solver.engine.cache.unsat.subset.methods import (
    SolverUnsatSubsetCacheMixin,
)
from pysymex._internal.core.solver.engine.caches import (
    CACHE_CONTEXT_MASK,
    CheckCacheEntry,
)
from pysymex._internal.core.solver.engine.types import SolverMixinContract
from pysymex._internal.core.solver.independence.protocols import has_to_z3
from pysymex._internal.core.z3.expression_ops import Z3ExpressionOps
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.solver.independence.optimizer import IndependenceOptimizer

logger = get_logger(__name__)
_SOLVER_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_IDENTITY_DISCRIMINATOR_PREFIX = "identity"
_SORT_STRING_CACHE_MAX_SIZE = 4096


_SORT_STRING_CACHE: OrderedDict[tuple[int, int], str] = OrderedDict()


def _get_sort_string(sort: z3.SortRef) -> str:
    ctx = sort.ctx
    ctx_id = id(ctx() if callable(ctx) else ctx)
    key = (ctx_id, sort.get_id())
    s = _SORT_STRING_CACHE.get(key)
    if s is None:
        s = str(sort)
        _SORT_STRING_CACHE[key] = s
        if len(_SORT_STRING_CACHE) > _SORT_STRING_CACHE_MAX_SIZE:
            _SORT_STRING_CACHE.popitem(last=False)
    else:
        _SORT_STRING_CACHE.move_to_end(key)
    return s


register_process_cache_clearer("solver.sort_string_cache", _SORT_STRING_CACHE.clear)


class SolverCacheMixin(
    SolverUnsatSubsetCacheMixin,
    SolverCheckCacheMixin,
    SolverMixinContract,
):
    """Synchronize incremental paths and cache structured SAT query results.

    Cache lookups validate structural discriminators after hash prefilters.
    ``UNKNOWN`` results are not stored as reusable SAT/UNSAT evidence.
    """

    if TYPE_CHECKING:
        active_path: list[z3.BoolRef]
        cache: OrderedDict[tuple[int, tuple[str | int, ...]], SolverResult]
        _cache_identity_constraints: dict[
            tuple[int, tuple[str | int, ...]],
            tuple[z3.BoolRef, ...],
        ]
        _cache_context_stack: list[int]
        _cache_hits: int
        _cache_index: dict[int, set[tuple[str | int, ...]]]
        _cache_size: int
        _check_cache: OrderedDict[int, list[CheckCacheEntry]]
        _constraint_fingerprint_cache: OrderedDict[int, list[tuple[z3.ExprRef, str]]]
        _constraint_fingerprint_cache_max_size: int
        _constraint_scope_stack: list[list[z3.BoolRef]]
        _hasher: ConstraintHasher
        _optimizer: IndependenceOptimizer
        pending_constraint_scope_stack: list[list[z3.BoolRef]]
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

    def _flush_pending_constraints(self) -> None:
        """Clear tracking for constraints already asserted by :meth:`add`."""
        for pending in self.pending_constraint_scope_stack:
            pending.clear()

    def _make_cache_key(self, constraints: list[z3.BoolRef]) -> int:
        """Create a scope-aware cache key for a constraint set."""
        return self._mix_cache_context(
            self._current_cache_context(),
            structural_hash(constraints, self._hasher),
        )

    def _constraint_fingerprint(self, constraint: z3.ExprRef) -> str:
        """Stable expression fingerprint used to isolate primary hash collisions."""
        if has_to_z3(constraint):
            constraint = constraint.to_z3()
        ast_id = getattr(constraint, "_symex_id", None)
        if ast_id is None:
            ast_id = constraint.get_id()
            try:
                setattr(constraint, "_symex_id", ast_id)
            except AttributeError:
                pass
        cached_entries = self._constraint_fingerprint_cache.get(ast_id)
        if cached_entries is not None:
            for cached_constraint, cached_fingerprint in cached_entries:
                if cached_constraint is constraint or Z3ExpressionOps.safe_eq(
                    cached_constraint,
                    constraint,
                ):
                    self._constraint_fingerprint_cache.move_to_end(ast_id)
                    return cached_fingerprint

        if hasattr(constraint, "sort"):
            sort = _get_sort_string(constraint.sort())
        else:
            sort = "<unknown>"
        h = getattr(constraint, "_symex_hash", None)
        if h is None:
            h = constraint.hash()
            try:
                setattr(constraint, "_symex_hash", h)
            except AttributeError:
                pass
        ctx = constraint.ctx
        ctx_id = id(ctx() if callable(ctx) else ctx)
        fingerprint = f"{h}:{sort}:{ctx_id}:{ast_id}"
        if cached_entries is None:
            self._constraint_fingerprint_cache[ast_id] = [(constraint, fingerprint)]
        else:
            cached_entries.append((constraint, fingerprint))
            self._constraint_fingerprint_cache.move_to_end(ast_id)
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

    def _constraints_identity_discriminator(
        self,
        constraints: list[z3.BoolRef],
    ) -> tuple[str | int, ...]:
        """Cheap discriminator for cold cache entries tied to retained object identities.

        Full collision-safe fingerprints are still used once a primary hash has
        more than one possible entry. The identity discriminator avoids expensive
        Z3 string rendering on the first store while retaining the exact
        BoolRef objects, so Python object ids cannot be reused while the entry
        remains live.
        """
        if not constraints:
            return (_IDENTITY_DISCRIMINATOR_PREFIX,)
        return (_IDENTITY_DISCRIMINATOR_PREFIX, *(id(c) for c in constraints))

    def _constraints_discriminator_for_constraints(
        self,
        constraints_obj: Iterable[z3.BoolRef],
        constraints: list[z3.BoolRef],
    ) -> tuple[str, ...]:
        """Secondary discriminator for cache collision detection."""
        _ = constraints_obj
        return self._constraints_discriminator(constraints)

    def _constraints_identity_discriminator_for_constraints(
        self,
        constraints_obj: Iterable[z3.BoolRef],
        constraints: list[z3.BoolRef],
    ) -> tuple[str | int, ...]:
        """Cheap identity discriminator for an input constraint collection."""
        _ = constraints_obj
        return self._constraints_identity_discriminator(constraints)

    @staticmethod
    def _is_identity_discriminator(discriminator: tuple[str | int, ...]) -> bool:
        """Return whether a discriminator is identity-retained."""
        return bool(discriminator) and discriminator[0] == _IDENTITY_DISCRIMINATOR_PREFIX

    def slice_prefix_for_query(
        self,
        prefix: list[z3.BoolRef],
        query: Iterable[z3.BoolRef] | z3.BoolRef,
    ) -> list[z3.BoolRef]:
        """Return the dependency-retained path prefix for a local query."""
        import z3

        q_list = [query] if isinstance(query, z3.ExprRef) else list(query)
        if not q_list:
            return prefix

        self._optimizer.sync_registered_path(prefix)

        combined_query = z3.And(*q_list) if len(q_list) > 1 else q_list[0]

        return self._optimizer.slice_for_query(prefix, combined_query)

    def _slice_prefix_for_suffix(
        self,
        prefix: list[z3.BoolRef],
        query: Iterable[z3.BoolRef] | z3.BoolRef,
    ) -> list[z3.BoolRef]:
        """Return the dependency-retained prefix selected by the optimizer."""
        return self.slice_prefix_for_query(prefix, query)

    def _cache_lookup(
        self,
        primary: int,
        discriminator: tuple[str | int, ...],
    ) -> SolverResult | None:
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
                "solver SAT cache hit primary=%d constraints=%d",
                primary,
                len(discriminator),
            )
        return result

    def _cache_store(
        self,
        primary: int,
        discriminator: tuple[str | int, ...],
        result: SolverResult,
        identity_constraints: tuple[z3.BoolRef, ...] | None = None,
    ) -> None:
        """Store a definitive cache entry, maintaining LRU order and index."""
        if not self._use_cache or result.is_unknown:
            return
        key = (primary, discriminator)
        if key in self.cache:
            self.cache[key] = result
            self.cache.move_to_end(key)
            self._cache_index.setdefault(primary, set()).add(discriminator)
            if identity_constraints is not None and self._is_identity_discriminator(
                discriminator,
            ):
                self._cache_identity_constraints[key] = identity_constraints
            if logger.state.trace_enabled:
                logger.trace("solver SAT cache refreshed primary=%d", primary)
            return
        while len(self.cache) >= self._cache_size:
            old_key, _ = self.cache.popitem(last=False)
            self._cache_identity_constraints.pop(old_key, None)
            old_primary, old_discriminator = old_key
            bucket = self._cache_index.get(old_primary)
            if bucket is not None:
                bucket.discard(old_discriminator)
                if not bucket:
                    del self._cache_index[old_primary]
        self.cache[key] = result
        self._cache_index.setdefault(primary, set()).add(discriminator)
        if identity_constraints is not None and self._is_identity_discriminator(discriminator):
            self._cache_identity_constraints[key] = identity_constraints
        if logger.state.trace_enabled:
            logger.trace(
                "solver SAT cache stored primary=%d size=%d sat=%s unsat=%s unknown=%s",
                primary,
                len(self.cache),
                result.is_sat,
                result.is_unsat,
                result.is_unknown,
            )
