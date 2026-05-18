# pysymex: Python Symbolic Execution & Formal Verification
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

"""Z3 Solver wrapper for pysymex.

This module provides a high-level interface to the Z3 theorem prover,
with incremental solving, structural caching, warm-start hints,
and exact UNKNOWN-preserving query results.

- IncrementalSolver: persistent solver with push/pop scope management
- Structural hash-based caching (no string conversion)
- Warm-start with previous model hints
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

import z3

from pysymex._typing import SolverProtocol
from pysymex.core.solver.constraints import ConstraintHasher, simplify_expr, structural_hash
from pysymex.core.solver.independence import ConstraintIndependenceOptimizer, has_to_z3
from pysymex.core.solver.unsat import UnsatCoreResult, extract_unsat_core
from pysymex.stats.registry import StatsRegistry
from pysymex.stats.types import EventType, Metadata
from pysymex.core.types.base import safe_z3_eq

logger = logging.getLogger(__name__)

_CACHE_CONTEXT_MASK = (1 << 128) - 1

has_to_z3 = has_to_z3


def _as_bool_constraint(value: object) -> z3.BoolRef | None:
    """Normalize a solver constraint candidate to a BoolRef when possible."""
    if isinstance(value, z3.BoolRef):
        return value
    if hasattr(value, "to_z3"):
        expr = value.to_z3()  # type: ignore
        if isinstance(expr, z3.BoolRef):
            return expr
    return None


def _normalize_constraint_iterable(values: Iterable[object]) -> list[z3.BoolRef]:
    """Normalize an iterable of constraint candidates into BoolRef constraints."""
    constraints: list[z3.BoolRef] = []
    for value in values:
        normalized = _as_bool_constraint(value)
        if normalized is not None:
            constraints.append(normalized)
    return constraints


_EMPTY_METADATA: Metadata = {}


def _emit_event(
    event_type: EventType,
    value: float = 0.0,
    metadata: Metadata | None = None,
) -> None:
    """Emit a solver telemetry event through the stats registry."""
    StatsRegistry().emit(event_type, value, metadata or _EMPTY_METADATA)


@dataclass(frozen=True, slots=True)
class SolverResult:
    """Result of a satisfiability check."""

    is_sat: bool
    is_unsat: bool
    is_unknown: bool
    model: z3.ModelRef | None = None

    @staticmethod
    def sat(model: z3.ModelRef | None) -> SolverResult:
        """Create a successful satisfiability result.

        Includes the Z3 model found by the solver, which describes a concrete
        witness for the symbolic path. Use this to extract counterexamples or
        guide further execution.
        """
        return SolverResult(is_sat=True, is_unsat=False, is_unknown=False, model=model)

    @staticmethod
    def unsat() -> SolverResult:
        """Create a result indicating the constraints are mathematically impossible."""
        return SolverResult(is_sat=False, is_unsat=True, is_unknown=False)

    @staticmethod
    def unknown() -> SolverResult:
        """Create a result indicating that Z3 could not decide within the timeout."""
        return SolverResult(is_sat=False, is_unsat=False, is_unknown=True)


@dataclass(frozen=True, slots=True)
class _CheckCacheEntry:
    """Cached low-level check result with exact context collision validation."""

    context: tuple[z3.BoolRef, ...]
    assumptions: tuple[z3.BoolRef, ...]
    result: SolverResult


@dataclass(frozen=True, slots=True)
class _AstTranslationCacheEntry:
    """Cached BoolRef translated into this solver's Z3 context."""

    source: z3.BoolRef
    translated: z3.BoolRef


class _StructuralCache:
    """Small LRU cache keyed by structural hashes instead of raw Z3 objects."""

    _MISSING = object()

    def __init__(self, maxsize: int = 512) -> None:
        self._data: OrderedDict[int, object] = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: int) -> tuple[bool, object | None]:
        """Retrieve a cached solver result for a given structural hash.

        Returns a tuple of (cache_hit, value). If hit, the item is moved to the
        end of the access list to maintain LRU semantics. The key should be
        the structural hash of the constraint set.
        """
        value = self._data.get(key, self._MISSING)
        if value is self._MISSING:
            return False, None
        self._data.move_to_end(key)
        return True, value

    def put(self, key: int, value: object) -> None:
        """Insert a result into the cache and maintain LRU order."""
        self._data[key] = value
        self._data.move_to_end(key)
        if len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def clear(self) -> None:
        """Empty the cache to reclaim memory."""
        self._data.clear()


class _ClearableCache(Protocol):
    """Clear."""

    def clear(self) -> None: ...


class _TranslatableZ3Expr(Protocol):
    """Z3 expression surface for context translation."""

    def translate(self, target: z3.Context) -> z3.ExprRef: ...


class IncrementalSolver:
    """High-performance incremental Z3 solver with structural caching.

    Maintains a single Z3 solver instance across an entire analysis,
    using push/pop scopes to manage constraint contexts. This avoids
    the overhead of creating new solvers and re-internalizing
    constraints for every query.

    Features:
    - Incremental solving with scope management
    - Structural hash-based result cache (O(1) lookup, no str() conversion)
    - Warm-start hints from previous models
    - Scope depth tracking
    - Statistics collection
    """

    def __init__(
        self,
        timeout_ms: int = 10000,
        cache_size: int = 50000,
        warm_start: bool = True,
        constraint_cache: object | None = None,
        use_cache: bool = True,
    ) -> None:
        """Initialize the incremental solver.

        Args:
            timeout_ms: Global Z3 solver timeout per query.
            cache_size: Maximum number of entries in the structural cache.
            warm_start: If True, uses models from previous SAT results as logic hints.
            constraint_cache: Optional shared cache for cross-instance reuse.
            use_cache: Master toggle for the internal structural-hash cache.
        """

        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        self._solver.set("auto_config", False)
        try:
            z3.set_param("parallel.enable", False)
            z3.set_param("sat.threads", 1)
            self._solver.set("threads", 1)
        except (z3.Z3Exception, OSError, ValueError) as exc:
            logger.debug("Failed to enable Z3 parallel mode: %s", exc)
        z3.set_param("timeout", timeout_ms)
        self._timeout_ms = timeout_ms
        self._scope_depth = 0
        self._cache: OrderedDict[tuple[int, tuple[int, ...]], SolverResult] = OrderedDict()
        self._cache_index: dict[int, set[tuple[int, ...]]] = {}
        self._check_cache: OrderedDict[int, list[_CheckCacheEntry]] = OrderedDict()
        self._check_cache_candidates: OrderedDict[int, None] = OrderedDict()
        self._z3_ast_cache: OrderedDict[int, list[_AstTranslationCacheEntry]] = OrderedDict()
        self._z3_ast_cache_hits = 0
        self._z3_ast_cache_misses = 0
        self._cache_context_stack: list[int] = [0]
        self._constraint_scope_stack: list[list[z3.BoolRef]] = [[]]
        self._pending_constraint_scope_stack: list[list[z3.BoolRef]] = [[]]
        self._cache_size = cache_size
        self._query_count = 0
        self._cache_hits = 0
        self._solver_time_ms = 0.0
        self._warm_start = warm_start
        self._last_models: deque[z3.ModelRef] = deque(maxlen=10)
        self._optimizer = ConstraintIndependenceOptimizer()
        self._constraint_cache = constraint_cache
        self._use_cache = use_cache
        self._is_unsat_context: set[int] = set()
        self._deadline_time: float | None = None

        self._active_path: list[z3.BoolRef] = []
        self._hasher = ConstraintHasher()
        self._last_set_timeout_ms: int | None = None
        self._last_set_rlimit: int | None = None

    def set_deadline(self, deadline_time: float | None) -> None:
        """Set an absolute wall-clock deadline for subsequent solver queries.

        ``deadline_time`` uses ``time.perf_counter()`` units. A ``None`` value
        clears the deadline and restores the configured per-query timeout.
        """
        self._deadline_time = deadline_time

    def _effective_timeout_ms(self) -> int:
        """Return the solver timeout clamped to the active wall-clock deadline."""
        if self._deadline_time is None:
            return self._timeout_ms
        remaining_ms = int((self._deadline_time - time.perf_counter()) * 1000)
        if remaining_ms <= 0:
            return 0
        return max(1, min(self._timeout_ms, remaining_ms))

    def _deadline_expired(self) -> bool:
        """Return whether the active wall-clock deadline has elapsed."""
        return self._deadline_time is not None and time.perf_counter() >= self._deadline_time

    def reset(self, force_new_solver: bool = True) -> None:
        """Reset the solver state and clear all caches instantaneously.

        This effectively starts a fresh Z3 session by resetting the solver,
        clearing the model history, and wiping the structural cache indices.
        Used between independent analysis runs or during resource recovery.
        """
        if True:  # Always force new solver for stability on Windows
            self._solver = z3.Solver()
            self._solver.set("timeout", self._timeout_ms)
            self._solver.set("auto_config", False)
            try:
                self._solver.set("threads", 1)
            except (z3.Z3Exception, OSError, ValueError):
                pass

        self._scope_depth = 0
        self._cache.clear()
        self._cache_index.clear()
        self._check_cache.clear()
        self._check_cache_candidates.clear()
        self._z3_ast_cache.clear()
        self._z3_ast_cache_hits = 0
        self._z3_ast_cache_misses = 0
        self._cache_context_stack = [0]
        self._constraint_scope_stack = [[]]
        self._pending_constraint_scope_stack = [[]]
        self._last_models.clear()
        self._optimizer.reset()
        self._is_unsat_context.clear()
        self._active_path.clear()
        self._hasher = ConstraintHasher()
        self._deadline_time = None
        self._last_set_timeout_ms = None
        self._last_set_rlimit = None

    def _expr_equal(self, a: z3.BoolRef, b: z3.BoolRef) -> bool:
        """Return semantic equality for two constraints with a fast hash pre-check."""
        if a is b:
            return True
        if safe_z3_eq(a, b):
            return True
        if self._hasher.hash_expr(a) != self._hasher.hash_expr(b):
            return False
        return str(a) == str(b)

    def _ast_signature_key(self, expr: z3.BoolRef, target_ctx: object) -> int:
        """Return a safe prefilter key for the per-solver Z3 AST translation cache."""
        source_ctx: object = getattr(expr, "ctx", None)
        stack: list[z3.ExprRef] = [expr]
        seen: set[int] = set()
        decl_kinds: list[int] = []
        sort_kinds: list[int] = []

        while stack:
            current = stack.pop()
            current_id = current.get_id()
            if current_id in seen:
                continue
            seen.add(current_id)

            try:
                sort_kinds.append(current.sort().kind())
            except z3.Z3Exception:
                sort_kinds.append(-1)

            if z3.is_app(current):
                try:
                    decl_kinds.append(current.decl().kind())
                except z3.Z3Exception:
                    decl_kinds.append(-1)
                for index in range(current.num_args()):
                    stack.append(current.arg(index))
            elif z3.is_quantifier(current):
                quantifier = current
                decl_kinds.append(1 if quantifier.is_forall() else 2)
                for index in range(quantifier.num_vars()):
                    try:
                        sort_kinds.append(quantifier.var_sort(index).kind())
                    except z3.Z3Exception:
                        sort_kinds.append(-1)
                stack.append(quantifier.body())

        return hash(
            (
                self._hasher.hash_expr(expr),
                id(source_ctx),
                id(target_ctx),
                tuple(sorted(decl_kinds)),
                tuple(sorted(sort_kinds)),
            )
        )

    def _lookup_translated_ast(
        self,
        cache_key: int,
        source: z3.BoolRef,
    ) -> z3.BoolRef | None:
        """Lookup a translated BoolRef after collision validation against the source AST."""
        bucket = self._z3_ast_cache.get(cache_key)
        if bucket is None:
            self._z3_ast_cache_misses += 1
            return None

        self._z3_ast_cache.move_to_end(cache_key)
        for entry in bucket:
            try:
                if z3.eq(entry.source, source):
                    self._z3_ast_cache_hits += 1
                    return entry.translated
            except z3.Z3Exception:
                continue

        self._z3_ast_cache_misses += 1
        return None

    def _store_translated_ast(
        self,
        cache_key: int,
        source: z3.BoolRef,
        translated: z3.BoolRef,
    ) -> None:
        """Store a translated BoolRef in the per-solver LRU cache."""
        entry = _AstTranslationCacheEntry(source=source, translated=translated)
        bucket = self._z3_ast_cache.get(cache_key)
        if bucket is None:
            self._z3_ast_cache[cache_key] = [entry]
        else:
            bucket.append(entry)
            self._z3_ast_cache.move_to_end(cache_key)
        while len(self._z3_ast_cache) > self._cache_size:
            self._z3_ast_cache.popitem(last=False)

    def _translate_bool_constraint(self, constraint: z3.BoolRef) -> z3.BoolRef:
        """Translate a BoolRef into this solver's Z3 context with validated cache reuse."""
        target_ctx = z3.main_ctx()
        source_ctx: object = getattr(constraint, "ctx", None)
        if source_ctx == target_ctx:
            return constraint
        cache_key: int | None = None
        if self._use_cache:
            cache_key = self._ast_signature_key(constraint, target_ctx)
            cached = self._lookup_translated_ast(cache_key, constraint)
            if cached is not None:
                return cached

        try:
            raw_translated = cast("_TranslatableZ3Expr", constraint).translate(target_ctx)
            if not isinstance(raw_translated, z3.BoolRef):
                return constraint
            translated = raw_translated
        except z3.Z3Exception:
            return constraint

        if self._use_cache and cache_key is not None:
            self._store_translated_ast(cache_key, constraint, translated)
        return translated

    def _normalize_bool_constraint(self, value: object) -> z3.BoolRef | None:
        """Normalize and context-translate a solver constraint candidate."""
        normalized = _as_bool_constraint(value)
        if normalized is None:
            return None
        return self._translate_bool_constraint(normalized)

    def _normalize_bool_constraints(self, values: Iterable[object]) -> list[z3.BoolRef]:
        """Normalize an iterable into BoolRefs owned by this solver's Z3 context."""
        constraints: list[z3.BoolRef] = []
        for value in values:
            normalized = self._normalize_bool_constraint(value)
            if normalized is not None:
                constraints.append(normalized)
        return constraints

    def _common_prefix_len(self, target: list[z3.BoolRef]) -> int:
        """Return common prefix length between synchronized and target paths."""
        limit = min(len(self._active_path), len(target))
        idx = 0
        while idx < limit and self._expr_equal(self._active_path[idx], target[idx]):
            idx += 1
        return idx

    def _sync_path(self, target_prefix: list[z3.BoolRef]) -> None:
        """Synchronize solver ambient context to *target_prefix* in O(delta) scopes.

        Each prefix element is represented by one push-scope frame, so we can
        pop exactly the divergent suffix and push only the missing delta.
        """
        lcp = self._common_prefix_len(target_prefix)

        while len(self._active_path) > lcp:
            self.pop()
            self._active_path.pop()

        for constraint in target_prefix[lcp:]:
            self.push()
            try:
                self.add(constraint)
            except z3.Z3Exception:
                try:
                    self.pop()
                except z3.Z3Exception:
                    logger.debug(
                        "Solver scope cleanup failed after sync-path add failure",
                        exc_info=True,
                    )
                raise
            self._active_path.append(constraint)

    @staticmethod
    def _mix_cache_context(seed: int, value: int) -> int:
        """Combine cache context values deterministically."""
        return ((seed * 1000003) ^ (value + 0x9E3779B97F4A7C15)) & _CACHE_CONTEXT_MASK

    def _current_cache_context(self) -> int:
        """Return the cache context for the current ambient solver state."""
        return self._cache_context_stack[-1]

    def _pending_assumptions(self) -> tuple[z3.BoolRef, ...]:
        """Return lazily added constraints that should participate in checks."""
        assumptions: list[z3.BoolRef] = []
        for scope_constraints in self._pending_constraint_scope_stack:
            assumptions.extend(scope_constraints)
        return tuple(assumptions)

    def _flush_pending_constraints(self) -> None:
        """Assert lazily added constraints into the underlying Z3 solver."""
        for pending in self._pending_constraint_scope_stack:
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

    @staticmethod
    def _constraints_discriminator(constraints: list[z3.BoolRef]) -> tuple[int, ...]:
        """Secondary discriminator to safely resolve potential structural hash collisions.

        While structural_hash is fast, it is theoretically possible for different
        expressions to share a hash. This discriminator uses the built-in Z3 hashes
        of individual constraints, which are based on internal expression pointers,
        to provide a secondary layer of identity verification.
        """
        if not constraints:
            return ()
        hashes: list[int] = []
        for c in constraints:
            if has_to_z3(c):
                z3_c = c.to_z3()
                hashes.append(hash(z3_c))
            else:
                hashes.append(hash(c))
        return tuple(sorted(hashes))

    def _constraints_discriminator_for_constraints(
        self,
        constraints_obj: Iterable[z3.BoolRef],
        constraints: list[z3.BoolRef],
    ) -> tuple[int, ...]:
        """Secondary discriminator with O(1) support for hashed constraint chains."""
        hash_value_getter = getattr(constraints_obj, "hash_value", None)
        if callable(hash_value_getter):
            try:
                hv = hash_value_getter()
            except (AttributeError, TypeError, RuntimeError) as exc:
                logger.debug("Failed to get hash value from constraint chain: %s", exc)
                hv = None
            if isinstance(hv, int):
                return (len(constraints), hv)
        return self._constraints_discriminator(constraints)

    def _slice_prefix_for_suffix(
        self, prefix: list[z3.BoolRef], query: Iterable[z3.BoolRef] | z3.BoolRef
    ) -> list[z3.BoolRef]:
        """Perform robust Constraint Slicing (Independence) using the optimizer."""
        import z3

        q_list = [query] if isinstance(query, z3.ExprRef) else list(query)
        if not q_list:
            return prefix

        for c in prefix:
            self._optimizer.register_constraint(c)

        combined_query = z3.And(*q_list) if len(q_list) > 1 else q_list[0]

        sliced = self._optimizer.slice_for_query(prefix, combined_query)
        return sliced

    def _cache_lookup(self, primary: int, discriminator: tuple[int, ...]) -> SolverResult | None:
        """Lookup a cached result, verifying the secondary discriminator."""
        if not self._use_cache:
            return None
        bucket = self._cache_index.get(primary)
        if bucket is None:
            return None
        if discriminator not in bucket:
            logger.debug("SAT cache collision detected")
            return None
        key = (primary, discriminator)
        result = self._cache.get(key)
        if result is None:
            return None
        self._cache_hits += 1
        self._cache.move_to_end(key)
        return result

    def _cache_store(
        self, primary: int, discriminator: tuple[int, ...], result: SolverResult
    ) -> None:
        """Store a cache entry, maintaining LRU order and index."""
        key = (primary, discriminator)
        if key in self._cache:
            self._cache[key] = result
            self._cache.move_to_end(key)
            self._cache_index.setdefault(primary, set()).add(discriminator)
            return
        while len(self._cache) >= self._cache_size:
            old_key, _ = self._cache.popitem(last=False)
            old_primary, old_discriminator = old_key
            bucket = self._cache_index.get(old_primary)
            if bucket is not None:
                bucket.discard(old_discriminator)
                if not bucket:
                    del self._cache_index[old_primary]
        self._cache[key] = result
        self._cache_index.setdefault(primary, set()).add(discriminator)

    def _current_constraint_context(self) -> tuple[z3.BoolRef, ...]:
        """Return the currently asserted constraints in chronological scope order."""
        constraints: list[z3.BoolRef] = []
        for scope_constraints in self._constraint_scope_stack:
            constraints.extend(scope_constraints)
        return tuple(constraints)

    def _same_constraint_sequence(
        self,
        left: tuple[z3.BoolRef, ...],
        right: tuple[z3.BoolRef, ...],
    ) -> bool:
        """Return whether two cached constraint sequences are structurally identical."""
        if len(left) != len(right):
            return False
        for left_constraint, right_constraint in zip(left, right, strict=True):
            if left_constraint is right_constraint:
                continue
            if safe_z3_eq(left_constraint, right_constraint):
                continue
            if self._hasher.hash_expr(left_constraint) != self._hasher.hash_expr(right_constraint):
                return False
            if not safe_z3_eq(left_constraint, right_constraint):
                return False
        return True

    def _make_check_cache_key(self, assumptions: tuple[z3.BoolRef, ...]) -> int:
        """Create a cache key for the active asserted context plus assumptions."""
        assumption_hash = structural_hash(list(assumptions), self._hasher)
        return self._mix_cache_context(
            self._current_cache_context(),
            self._mix_cache_context(len(assumptions), assumption_hash),
        )

    def _check_cache_lookup(
        self,
        primary: int,
        context: tuple[z3.BoolRef, ...],
        assumptions: tuple[z3.BoolRef, ...],
    ) -> SolverResult | None:
        """Lookup a low-level check result after exact collision validation."""
        if not self._use_cache:
            return None
        entries = self._check_cache.get(primary)
        if entries is None:
            return None
        for entry in entries:
            if self._same_constraint_sequence(
                entry.context, context
            ) and self._same_constraint_sequence(entry.assumptions, assumptions):
                self._cache_hits += 1
                self._check_cache.move_to_end(primary)
                return entry.result
        logger.debug("check() cache collision detected")
        return None

    def _check_cache_store(
        self,
        primary: int,
        context: tuple[z3.BoolRef, ...],
        assumptions: tuple[z3.BoolRef, ...],
        result: SolverResult,
    ) -> None:
        """Store a low-level check result without caching UNKNOWN answers."""
        if not self._use_cache or result.is_unknown:
            return
        entry = _CheckCacheEntry(context=context, assumptions=assumptions, result=result)
        entries = self._check_cache.get(primary)
        if entries is None:
            self._check_cache[primary] = [entry]
        else:
            entries.append(entry)
            self._check_cache.move_to_end(primary)
        while len(self._check_cache) > self._cache_size:
            self._check_cache.popitem(last=False)

    def _admit_check_cache_candidate(self, primary: int) -> bool:
        """Return whether a check key has appeared before and should be cached."""
        if primary in self._check_cache_candidates:
            self._check_cache_candidates.move_to_end(primary)
            return True
        self._check_cache_candidates[primary] = None
        while len(self._check_cache_candidates) > self._cache_size:
            self._check_cache_candidates.popitem(last=False)
        return False

    def constraint_optimizer(self) -> ConstraintIndependenceOptimizer:
        """Expose the shared constraint optimizer for graph-based analyses."""
        return self._optimizer

    def push(self) -> None:
        """Push a new constraint scope."""
        self._solver.push()
        self._scope_depth += 1
        self._cache_context_stack.append(self._current_cache_context())
        self._constraint_scope_stack.append([])
        self._pending_constraint_scope_stack.append([])

    def pop(self) -> None:
        """Pop the current constraint scope."""
        if self._scope_depth > 0:
            try:
                self._solver.pop()
            except (z3.Z3Exception, OSError, RuntimeError) as exc:
                logger.debug("Solver pop failed at depth %d: %s", self._scope_depth, exc)
                self.reset(force_new_solver=True)
                return

            self._scope_depth -= 1
            self._cache_context_stack.pop()
            self._constraint_scope_stack.pop()
            self._pending_constraint_scope_stack.pop()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add constraints to the solver at the current scope."""
        from pysymex.core.constants import Z3_FALSE, Z3_TRUE

        processed_constraints: list[z3.BoolRef] = []

        for c in constraints:
            if c is Z3_TRUE:
                continue
            if c is Z3_FALSE:
                processed_constraints.append(c)
                continue

            normalized = self._normalize_bool_constraint(c)
            if normalized is not None:
                processed_constraints.append(normalized)

        if not processed_constraints:
            return

        self._constraint_scope_stack[-1].extend(processed_constraints)
        if self._use_cache:
            updated_context = self._current_cache_context()
            for c in processed_constraints:
                updated_context = self._mix_cache_context(updated_context, c.hash())
            self._cache_context_stack[-1] = updated_context
        self._pending_constraint_scope_stack[-1].extend(processed_constraints)
        self._solver.add(*processed_constraints)

    def extend_path(self, constraints: Iterable[z3.BoolRef]) -> None:
        """Permanently extend the ambient path with new constraints.

        Adds constraints at the current scope and updates _active_path.
        Used by the symbolic executor to commit verified path segments.
        """
        c_list = list(constraints)
        if not c_list:
            return
        self.add(*c_list)
        self._active_path.extend(c_list)

    def enter_scope(self, constraints: list[z3.BoolRef]) -> None:
        """Push a new scope and add constraints. Used for path exploration."""
        self.push()
        for c in constraints:
            try:
                self.add(c)
            except z3.Z3Exception:
                logger.debug("Failed to add constraint in enter_scope", exc_info=True)

    def leave_scope(self) -> None:
        """Leave the current scope (alias for pop)."""
        self.pop()

    def check(self, *assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
        """Check satisfiability with optional assumptions.

        Args:
            assumptions: Additional assumptions for this check only.
            need_model: Whether to materialize and return a model for SAT results.
                       Defaults to False for performance.

        Returns:
            SolverResult indicating sat/unsat/unknown with optional model.
        """
        self._query_count += 1

        num_clauses = len(self._active_path) + len(assumptions)
        _emit_event(EventType.SOLVER_QUERY, 0.0, {"clauses": num_clauses})

        effective_timeout_ms = self._effective_timeout_ms()
        if effective_timeout_ms <= 0:
            _emit_event(EventType.SOLVER_UNKNOWN, 1.0)
            return SolverResult.unknown()

        assumption_tuple = tuple(assumptions)
        check_cache_key: int | None = None
        check_context: tuple[z3.BoolRef, ...] | None = None
        should_store_check_cache = False
        if self._use_cache and not need_model:
            check_cache_key = self._make_check_cache_key(assumption_tuple)
            if check_cache_key in self._check_cache:
                check_context = self._current_constraint_context()
                cached = self._check_cache_lookup(
                    check_cache_key,
                    check_context,
                    assumption_tuple,
                )
                if cached is not None:
                    if cached.is_sat:
                        _emit_event(EventType.SOLVER_SAT, 1.0)
                    elif cached.is_unsat:
                        _emit_event(EventType.SOLVER_UNSAT, 1.0)
                    return cached
            should_store_check_cache = self._admit_check_cache_candidate(check_cache_key)

        if effective_timeout_ms != self._last_set_timeout_ms:
            self._solver.set("timeout", effective_timeout_ms)
            self._last_set_timeout_ms = effective_timeout_ms

        rlimit = int(effective_timeout_ms * 2500)
        if rlimit != self._last_set_rlimit:
            self._solver.set("rlimit", rlimit)
            self._last_set_rlimit = rlimit
        start = time.perf_counter()

        try:
            self._flush_pending_constraints()
            result = self._solver.check(*assumption_tuple)
        except Exception:
            result = z3.unknown

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._solver_time_ms += elapsed_ms

        if result == z3.sat:
            _emit_event(EventType.SOLVER_SAT, 1.0)
            if need_model:
                model = self._solver.model()
                if self._warm_start:
                    self._last_models.append(model)
                return SolverResult.sat(model)
            result_obj = SolverResult.sat(None)
        elif result == z3.unsat:
            _emit_event(EventType.SOLVER_UNSAT, 1.0)
            result_obj = SolverResult.unsat()
        else:
            _emit_event(EventType.SOLVER_UNKNOWN, 1.0)
            result_obj = SolverResult.unknown()

        if check_cache_key is not None and should_store_check_cache:
            if check_context is None:
                check_context = self._current_constraint_context()
            self._check_cache_store(check_cache_key, check_context, assumption_tuple, result_obj)
        return result_obj

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Check constraints and preserve ``unknown`` instead of collapsing it.

        Uses constraint independence optimization to slice the constraints
        down to only what is necessary for the current suffix.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            Full SAT/UNSAT/UNKNOWN solver result.
        """
        import z3

        raw_list = constraints if isinstance(constraints, list) else list(constraints)
        constraint_list = self._normalize_bool_constraints(raw_list)

        if not constraint_list:
            return SolverResult.sat(None)

        if len(constraint_list) == 1:
            c = constraint_list[0]
            if z3.is_true(c):
                return SolverResult.sat(None)
            if z3.is_false(c):
                return SolverResult.unsat()

        from pysymex.core.solver.constraints import structural_hash

        cache_hv = structural_hash(constraint_list, self._hasher)
        cache_key = self._mix_cache_context(0, cache_hv)

        bucket = self._cache_index.get(cache_key)
        cache_disc = (
            ()
            if bucket is None
            else self._constraints_discriminator_for_constraints(constraints, constraint_list)
        )

        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None:
            return cached

        if known_sat_prefix_len is not None and 0 <= known_sat_prefix_len <= len(constraint_list):
            prefix = constraint_list[:known_sat_prefix_len]
            suffix = constraint_list[known_sat_prefix_len:]
        else:
            prefix = []
            suffix = constraint_list

        for c in suffix:
            if z3.is_false(c):
                result = SolverResult.unsat()
                self._cache_store(cache_key, cache_disc, result)
                return result

        is_aligned = known_sat_prefix_len is not None and known_sat_prefix_len == len(
            self._active_path
        )
        if is_aligned:
            sliced_prefix = prefix
        else:
            sliced_prefix = (
                prefix
                if not prefix
                else (self._slice_prefix_for_suffix(prefix, suffix) if suffix else prefix)
            )

        try:
            self._sync_path(sliced_prefix)
        except z3.Z3Exception:
            result = SolverResult.unknown()
            self._cache_store(cache_key, cache_disc, result)
            return result

        if not suffix:
            result = SolverResult.sat(None)
            self._cache_store(cache_key, cache_disc, result)
            return result

        if self._warm_start and self._last_models:
            latest_model = self._last_models[-1]
            try:
                if len(suffix) <= 20 and all(
                    z3.is_true(latest_model.eval(c, model_completion=True)) for c in suffix
                ):
                    result = SolverResult.sat(latest_model)
                    self._cache_store(cache_key, cache_disc, result)
                    return result
            except (z3.Z3Exception, AttributeError):
                pass

        use_push_pop = True

        result = SolverResult.unknown()
        pushed = False
        try:
            if use_push_pop:
                self.push()
                pushed = True
            self.add(*suffix)
            result = self.check(need_model=False)
        except z3.Z3Exception:
            logger.debug("Solver query failed; preserving path as UNKNOWN", exc_info=True)
        finally:
            if pushed:
                try:
                    self.pop()
                except z3.Z3Exception:
                    logger.debug("Solver scope pop failed after UNKNOWN query", exc_info=True)
                    result = SolverResult.unknown()

        self._cache_store(cache_key, cache_disc, result)
        return result

    def is_sat(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Check if constraints are satisfiable, preserving paths on ``unknown``.

        This legacy boolean API treats solver ``unknown`` as potentially SAT so
        path exploration does not silently prune feasible states. Call
        :meth:`check_sat_result` where the caller must distinguish unknown from
        definite SAT, such as bug-detector feasibility checks.
        """
        result = self.check_sat_result(
            constraints,
            known_sat_prefix_len=known_sat_prefix_len,
        )
        if result.is_unknown:
            return True
        return result.is_sat

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Check satisfiability with full result caching.

        Returns the full SolverResult (including model if SAT).

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            SolverResult with sat/unsat/unknown and optional model.
        """
        translated_constraints = self._normalize_bool_constraints(constraints)
        cache_key = self._make_cache_key(translated_constraints)
        cache_disc = self._constraints_discriminator(translated_constraints)
        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None and (not cached.is_sat or cached.model is not None):
            return cached

        result_obj = SolverResult.unknown()
        pushed = False
        try:
            self._solver.push()
            pushed = True
            self._solver.add(translated_constraints)
            result_obj = self.check(need_model=True)
        except z3.Z3Exception:
            logger.debug("Cached solver query failed; preserving result as UNKNOWN", exc_info=True)
        finally:
            if pushed:
                try:
                    self._solver.pop()
                except z3.Z3Exception:
                    logger.debug(
                        "Cached solver scope pop failed after UNKNOWN query", exc_info=True
                    )
                    result_obj = SolverResult.unknown()

        self._cache_store(cache_key, cache_disc, result_obj)
        return result_obj

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Get a satisfying model for the constraints.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            A Z3 model if satisfiable, None otherwise.
        """
        result = self.check_sat_cached(constraints)
        return result.model if result.is_sat else None

    def get_model_string(self, constraints: list[z3.BoolRef]) -> str | None:
        """Get a string representation of a satisfying model."""
        model = self.get_model(constraints)
        if model is not None:
            return str(model)
        return None

    def extract_counterexample(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str] | None = None,
    ) -> dict[str, object]:
        """Extract a counterexample as a dictionary.

        Args:
            constraints: List of Z3 boolean constraints.
            variables: Optional list of variable names to extract.

        Returns:
            Dictionary mapping variable names to concrete values.
        """
        model = self.get_model(constraints)
        if model is None:
            return {}
        result: dict[str, object] = {}
        for decl in model.decls():
            name = decl.name()
            value = model[decl]
            if name.endswith("_int"):
                base = name[:-4]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["int"] = value
            elif name.endswith("_bool"):
                base = name[:-5]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["bool"] = value
            elif name.endswith("_is_int"):
                base = name[:-7]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["is_int"] = value
            elif name.endswith("_is_bool"):
                base = name[:-8]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["is_bool"] = value
            elif name.endswith("_str"):
                base = name[:-4]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["str"] = value
            elif name.endswith("_len"):
                base = name[:-4]
                bucket = cast("dict[str, object]", result.setdefault(base, {}))
                bucket["len"] = value
            else:
                result[name] = {"value": value}
        formatted: dict[str, object] = {}
        for var, info in result.items():
            if isinstance(info, dict):
                info_d = cast("dict[str, object]", info)
                is_int_val = info_d.get("is_int")
                if z3.is_true(is_int_val) or str(is_int_val) == "True":
                    formatted[var] = {"type": "int", "value": info_d.get("int")}
                else:
                    is_bool_val = info_d.get("is_bool")
                    if z3.is_true(is_bool_val) or str(is_bool_val) == "True":
                        formatted[var] = {"type": "bool", "value": info_d.get("bool")}
                    elif "str" in info_d:
                        formatted[var] = {"type": "str", "value": info_d.get("str")}
                    elif "int" in info_d:
                        formatted[var] = {"type": "int", "value": info_d.get("int")}
                    else:
                        formatted[var] = {"type": "unknown", "value": info_d}
            else:
                formatted[var] = {"type": "unknown", "value": info}
        if variables is not None:
            formatted = {k: v for k, v in formatted.items() if k in variables}
        return formatted

    def implies(self, antecedent: z3.BoolRef, consequent: z3.BoolRef) -> bool:
        """Check if antecedent implies consequent.

        Uses the existing solver with push/pop instead of creating a new one.

        Args:
            antecedent: The assumption.
            consequent: The conclusion.

        Returns:
            True if antecedent => consequent is valid.
        """
        normalized_antecedent = self._normalize_bool_constraint(antecedent)
        normalized_consequent = self._normalize_bool_constraint(consequent)
        if normalized_antecedent is None or normalized_consequent is None:
            return False

        self._flush_pending_constraints()
        pushed = False
        try:
            self._solver.push()
            pushed = True
            self._solver.add(normalized_antecedent, z3.Not(normalized_consequent))
            result = self._solver.check()
        except z3.Z3Exception:
            logger.debug(
                "Implication check failed; treating implication as unproven", exc_info=True
            )
            return False
        finally:
            if pushed:
                try:
                    self._solver.pop()
                except z3.Z3Exception:
                    logger.debug("Implication check scope cleanup failed", exc_info=True)
                    self.reset(force_new_solver=True)
                    return False
        return result == z3.unsat

    def simplify(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Simplify a Z3 expression."""
        return simplify_expr(expr)

    def get_unsat_core(self, constraints: list[z3.BoolRef]) -> UnsatCoreResult | None:
        """Extract the minimal unsatisfiable core from UNSAT constraints.

        Uses Z3's unsat_core mechanism to identify which constraints
        are responsible for infeasibility.

        Args:
            constraints: List of Z3 constraints known (or suspected) to be UNSAT.

        Returns:
            UnsatCoreResult with the minimal core, or None if not UNSAT.
        """
        return extract_unsat_core(constraints, timeout_ms=self._timeout_ms)

    def get_stats(self) -> dict[str, object]:
        """Get solver statistics."""
        return {
            "queries": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "check_cache_size": len(self._check_cache),
            "check_cache_candidates": len(self._check_cache_candidates),
            "z3_ast_cache_hits": self._z3_ast_cache_hits,
            "z3_ast_cache_misses": self._z3_ast_cache_misses,
            "z3_ast_cache_hit_rate": round(
                self._z3_ast_cache_hits
                / max(1, self._z3_ast_cache_hits + self._z3_ast_cache_misses),
                4,
            ),
            "z3_ast_cache_size": len(self._z3_ast_cache),
            "scope_depth": self._scope_depth,
            "solver_time_ms": round(self._solver_time_ms, 2),
            "warm_start_models": len(self._last_models),
        }

    def __repr__(self) -> str:
        return (
            f"IncrementalSolver(queries={self._query_count}, "
            f"cache_hits={self._cache_hits}, scope={self._scope_depth})"
        )


DEFAULT_SOLVER_TIMEOUT_MS: int = 5000


def create_solver(timeout_ms: int = DEFAULT_SOLVER_TIMEOUT_MS) -> z3.Solver:
    """Create a Z3 Solver with a mandatory timeout.

    Every solver in the engine MUST go through this factory to prevent
    indefinite hangs on complex Sequence/Array theories.

    Args:
        timeout_ms: Timeout in milliseconds. Defaults to 5 000 ms.

    Returns:
        A configured ``z3.Solver`` ready for use.
    """
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.set("auto_config", False)
    return solver


_SOLVER_CACHES: list[_ClearableCache] = []

_IS_SAT_CACHE = _StructuralCache(maxsize=512)
_MODEL_CACHE = _StructuralCache(maxsize=512)
_PROVE_CACHE = _StructuralCache(maxsize=512)

_SOLVER_CACHES.extend([_IS_SAT_CACHE, _MODEL_CACHE, _PROVE_CACHE])

_active_solver_var: contextvars.ContextVar[SolverProtocol | None] = contextvars.ContextVar(
    "_active_solver_var", default=None
)

active_incremental_solver = _active_solver_var


def is_satisfiable(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Check if a list of constraints is satisfiable."""
    c_list = list(constraints)
    solver = _active_solver_var.get()

    if solver is not None:
        return solver.is_sat(c_list, known_sat_prefix_len=known_sat_prefix_len)
    return _is_satisfiable_cached(c_list)


class _ThreadLocalSolver(threading.local):
    def __init__(self) -> None:
        self.solver: IncrementalSolver | None = None


_thread_local_solver = _ThreadLocalSolver()


def _is_satisfiable_cached(constraints: Iterable[z3.BoolRef]) -> bool:
    """Standalone satisfiability check routed through the IncrementalSolver SSoT."""
    solver = _thread_local_solver.solver
    if solver is None:
        solver = IncrementalSolver(timeout_ms=5000, use_cache=True)
        _thread_local_solver.solver = solver
    return solver.is_sat(list(constraints))


def get_model(constraints: Iterable[object] | z3.BoolRef) -> z3.ModelRef | None:
    """Get a Z3 model for satisfiable constraints."""
    from pysymex.core.memory.cow import ConstraintChain

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        typed_constraints = _normalize_constraint_iterable(constraints)

    solver = _active_solver_var.get()
    if solver is not None:
        return solver.get_model(typed_constraints)
    return _get_model_cached(typed_constraints)


def _get_model_cached(constraints: Iterable[object] | z3.BoolRef) -> z3.ModelRef | None:
    """Standalone model extraction routed through the IncrementalSolver SSoT."""
    from pysymex.core.memory.cow import ConstraintChain

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    if isinstance(constraints, z3.BoolRef):
        typed_constraints = [constraints]
    else:
        typed_constraints = _normalize_constraint_iterable(constraints)
    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    return solver.get_model(typed_constraints)


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Get a model string for satisfiable constraints."""
    model = get_model(constraints)
    return str(model) if model else None


def prove(claim: z3.BoolRef) -> bool:
    """Prove that a claim is always true.

    Uses the IncrementalSolver SSoT over the negated claim.
    """
    solver = IncrementalSolver(timeout_ms=5000, use_cache=False)
    result = solver.check_sat_cached([z3.Not(claim)])
    return result.is_unsat


def clear_solver_caches() -> None:
    """Clear all Z3 solver caches to release context memory.

    Call this between analysis runs (e.g., when scanning multiple files)
    to prevent unbounded memory growth from cached Z3 expressions.
    """
    for cached_fn in _SOLVER_CACHES:
        cached_fn.clear()
