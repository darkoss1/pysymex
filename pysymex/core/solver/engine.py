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
and portfolio solving for hard queries.

Rewritten for world-class performance.
- IncrementalSolver: persistent solver with push/pop scope management
- PortfolioSolver: parallel tactic execution for hard queries
- Structural hash-based caching (no string conversion)
- Warm-start with previous model hints
"""

from __future__ import annotations

import contextvars
import logging
import os
import time
import concurrent.futures
import multiprocessing as mp
import queue
from multiprocessing.queues import Queue as MpQueue
from multiprocessing.process import BaseProcess
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

import z3

from pysymex._typing import SolverProtocol
from pysymex.core.solver.constraints import ConstraintHasher, structural_hash
from pysymex.core.solver.independence import ConstraintIndependenceOptimizer
from pysymex.core.solver.unsat import UnsatCoreResult, extract_unsat_core
from pysymex.stats.registry import StatsRegistry
from pysymex.stats.types import EventType, Metadata

logger = logging.getLogger(__name__)

_CACHE_CONTEXT_MASK = (1 << 128) - 1


def _emit_event(
    event_type: EventType,
    value: float = 0.0,
    metadata: Metadata | None = None,
) -> None:
    """Emit a solver telemetry event through the stats registry."""
    StatsRegistry().emit(event_type, value, metadata)


__all__ = [
    "DEFAULT_SOLVER_TIMEOUT_MS",
    "IncrementalSolver",
    "PortfolioSolver",
    "SolverResult",
    "clear_solver_caches",
    "create_solver",
    "get_model",
    "get_model_string",
    "is_satisfiable",
    "prove",
]


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
        try:
            import os

            threads = max(1, os.cpu_count() or 1)
            z3.set_param("parallel.enable", True)
            z3.set_param("sat.threads", threads)
            self._solver.set("threads", threads)
        except (z3.Z3Exception, OSError, ValueError) as exc:
            logger.debug("Failed to enable Z3 parallel mode: %s", exc)
        z3.set_param("timeout", timeout_ms)
        self._timeout_ms = timeout_ms
        self._scope_depth = 0
        self._cache: OrderedDict[tuple[int, tuple[int, ...]], SolverResult] = OrderedDict()
        self._cache_index: dict[int, set[tuple[int, ...]]] = {}
        self._cache_context_stack: list[int] = [0]
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
        self._portfolio: PortfolioSolver | None = None
        self._escalation_threshold_ms: float = 500.0

        self._escalations: int = 0
        self._abandoned_solvers: list[z3.Solver] = []

        self._active_path: list[z3.BoolRef] = []
        self._hasher = ConstraintHasher()
        self._executor_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def reset(self) -> None:
        """Reset the solver state and clear all caches instantaneously.

        This effectively starts a fresh Z3 session by resetting the solver,
        clearing the model history, and wiping the structural cache indices.
        Used between independent analysis runs or during resource recovery.
        """
        self._solver.reset()
        self._scope_depth = 0
        self._cache.clear()
        self._cache_index.clear()
        self._cache_context_stack = [0]
        self._last_models.clear()
        self._optimizer.reset()
        self._is_unsat_context.clear()
        self._active_path.clear()
        self._hasher = ConstraintHasher()
        self._executor_pool.shutdown(wait=False, cancel_futures=True)
        self._executor_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def __del__(self) -> None:
        """Cleanup executor pool on garbage collection."""
        try:
            self._executor_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    def _expr_equal(self, a: z3.BoolRef, b: z3.BoolRef) -> bool:
        """Return semantic equality for two constraints with a fast hash pre-check."""
        if a is b:
            return True
        # Use hasher cache to avoid duplicate FFI calls
        cache = self._hasher._cache  # type: ignore[attr-defined]
        a_id = id(a)
        b_id = id(b)
        if a_id not in cache:
            cache[a_id] = a.hash()
        if b_id not in cache:
            cache[b_id] = b.hash()
        if cache[a_id] != cache[b_id]:
            return False
        try:
            return bool(z3.eq(a, b))
        except z3.Z3Exception:
            return str(a) == str(b)

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
            self.add(constraint)
            self._active_path.append(constraint)

    @staticmethod
    def _mix_cache_context(seed: int, value: int) -> int:
        """Combine cache context values deterministically."""
        return ((seed * 1000003) ^ (value + 0x9E3779B97F4A7C15)) & _CACHE_CONTEXT_MASK

    def _current_cache_context(self) -> int:
        """Return the cache context for the current ambient solver state."""
        return self._cache_context_stack[-1]

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
        return tuple(sorted(hash(c) for c in constraints))

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

    def constraint_optimizer(self) -> ConstraintIndependenceOptimizer:
        """Expose the shared constraint optimizer for graph-based analyses."""
        return self._optimizer

    def push(self) -> None:
        """Push a new constraint scope."""
        self._solver.push()
        self._scope_depth += 1
        self._cache_context_stack.append(self._current_cache_context())

    def pop(self) -> None:
        """Pop the current constraint scope."""
        if self._scope_depth > 0:
            self._solver.pop()
            self._scope_depth -= 1
            self._cache_context_stack.pop()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add constraints to the solver."""
        self._solver.add(*constraints)
        if constraints:
            updated_context = self._current_cache_context()
            constraint_hashes = sorted(
                structural_hash([constraint], self._hasher) for constraint in constraints
            )
            for constraint_hash in constraint_hashes:
                updated_context = self._mix_cache_context(updated_context, constraint_hash)
            self._cache_context_stack[-1] = updated_context

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

    def check(self, *assumptions: z3.BoolRef) -> SolverResult:
        """Check satisfiability with optional assumptions.

        Args:
            assumptions: Additional assumptions for this check only.

        Returns:
            SolverResult indicating sat/unsat/unknown with optional model.
        """
        self._query_count += 1

        num_clauses = len(self._active_path) + len(assumptions)
        _emit_event(EventType.SOLVER_QUERY, 0.0, {"clauses": num_clauses})

        self._solver.set("timeout", self._timeout_ms)
        rlimit = int(self._timeout_ms * 2500)
        self._solver.set("rlimit", rlimit)
        start = time.perf_counter()

        future = self._executor_pool.submit(self._solver.check, *assumptions)
        result: z3.CheckSatResult = z3.unknown
        try:
            result = future.result(timeout=self._timeout_ms / 1000.0 + 1.0)
        except concurrent.futures.TimeoutError:
            logger.error("Z3 solver completely hung. Abandoning solver instance.")
            result = z3.unknown

            self._abandoned_solvers.append(self._solver)

            old_path = list(self._active_path)
            self._solver = z3.Solver()
            self._solver.set("timeout", self._timeout_ms)
            try:
                import os

                threads = max(1, os.cpu_count() or 1)
                self._solver.set("threads", threads)
            except Exception as exc:
                logger.debug("Failed to configure threads on rebuilt solver: %s", exc)
            self._scope_depth = 0
            self._cache_context_stack = [0]
            self._active_path = []
            self._sync_path(old_path)
        except Exception:
            result = z3.unknown
        finally:
            if result != z3.unknown:
                self._solver.set("rlimit", 0)

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._solver_time_ms += elapsed_ms

        if result == z3.sat:
            _emit_event(EventType.SOLVER_SAT, 1.0)
            model = self._solver.model()
            if self._warm_start:
                self._last_models.append(model)
            return SolverResult.sat(model)
        elif result == z3.unsat:
            _emit_event(EventType.SOLVER_UNSAT, 1.0)
            return SolverResult.unsat()
        else:
            _emit_event(EventType.SOLVER_UNKNOWN, 1.0)
            return SolverResult.unknown()

    def is_sat(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Check if constraints are satisfiable, with caching.

        Uses constraint independence optimization to slice the constraints
        down to only what is necessary for the current suffix.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            True if satisfiable, False otherwise.
        """
        constraint_list = constraints if isinstance(constraints, list) else list(constraints)

        if not constraint_list:
            return True

        if len(constraint_list) == 1:
            c = constraint_list[0]
            if z3.is_true(c):
                return True
            if z3.is_false(c):
                return False

        from pysymex.core.solver.constraints import structural_hash

        cache_hv = structural_hash(constraint_list, self._hasher)
        cache_key = self._mix_cache_context(0, cache_hv)
        cache_disc = (
            ()
            if len(constraint_list) <= 5
            else self._constraints_discriminator_for_constraints(constraints, constraint_list)
        )

        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None:
            return cached.is_sat

        if known_sat_prefix_len is not None and 0 <= known_sat_prefix_len <= len(constraint_list):
            prefix = constraint_list[:known_sat_prefix_len]
            suffix = constraint_list[known_sat_prefix_len:]
        else:
            prefix = []
            suffix = constraint_list

        for c in suffix:
            if z3.is_false(c):
                self._cache_store(cache_key, cache_disc, SolverResult.unsat())
                return False

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

        self._sync_path(sliced_prefix)

        if not suffix:
            result = SolverResult.sat(None)
            self._cache_store(cache_key, cache_disc, result)
            return True

        use_push_pop = known_sat_prefix_len is not None or len(self._active_path) > 0

        if use_push_pop:
            self._solver.push()

        start_ns = time.perf_counter()
        try:
            self._solver.add(*suffix)
            result = self.check()
        finally:
            if use_push_pop:
                self._solver.pop()
        elapsed_ms = (time.perf_counter() - start_ns) * 1000

        if result.is_unknown:
            escalated_constraints = sliced_prefix + suffix
            escalated = self._try_escalate(escalated_constraints, elapsed_ms, force=True)
            if escalated is not None and not escalated.is_unknown:
                self._cache_store(cache_key, cache_disc, escalated)
                return escalated.is_sat
            return True

        self._cache_store(cache_key, cache_disc, result)
        return result.is_sat

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Check satisfiability with full result caching.

        Returns the full SolverResult (including model if SAT).

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            SolverResult with sat/unsat/unknown and optional model.
        """
        cache_key = self._make_cache_key(constraints)
        cache_disc = self._constraints_discriminator(constraints)
        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None and (not cached.is_sat or cached.model is not None):
            return cached

        self._solver.push()
        try:
            self._solver.add(constraints)
            result_obj = self.check()
        finally:
            self._solver.pop()

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
        self._solver.push()
        try:
            self._solver.add(antecedent, z3.Not(consequent))
            result = self._solver.check()
        finally:
            self._solver.pop()
        return result == z3.unsat

    def simplify(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Simplify a Z3 expression."""
        return z3.simplify(expr)

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

    def _try_escalate(
        self,
        constraints: list[z3.BoolRef],
        elapsed_ms: float,
        force: bool = False,
    ) -> SolverResult | None:
        """Escalate to :class:`PortfolioSolver` when a query is too slow.

        Called by :meth:`is_sat` when a single-solver ``check()`` returns
        ``unknown`` or exceeds :attr:`_escalation_threshold_ms`.

        Args:
            constraints: Constraints to re-check with the portfolio solver.
            elapsed_ms: Time the primary solver spent on this query.
            force: When True, bypass the time threshold guard (used when
                the primary solver returned ``unknown`` quickly — e.g. via
                an internal resource exhaustion).

        Returns:
            A definitive result, or ``None`` if escalation also fails.
        """
        if not force and elapsed_ms < self._escalation_threshold_ms:
            return None

        self._escalations += 1
        if self._portfolio is None:
            self._portfolio = PortfolioSolver(
                timeout_ms=self._timeout_ms * 2,
                fast_timeout_ms=int(self._escalation_threshold_ms),
            )

        logger.debug(
            "Auto-escalating to portfolio solver (elapsed=%.1fms, threshold=%.1fms)",
            elapsed_ms,
            self._escalation_threshold_ms,
        )
        return self._portfolio.check_hard(constraints)

    def get_stats(self) -> dict[str, object]:
        """Get solver statistics."""
        return {
            "queries": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "scope_depth": self._scope_depth,
            "solver_time_ms": round(self._solver_time_ms, 2),
            "warm_start_models": len(self._last_models),
            "escalations": self._escalations,
        }

    def __repr__(self) -> str:
        return (
            f"IncrementalSolver(queries={self._query_count}, "
            f"cache_hits={self._cache_hits}, scope={self._scope_depth})"
        )


class PortfolioSolver:
    """Parallel portfolio solver with active process termination and true Cube-and-Conquer."""

    TACTICS = ["smt", "qflia", "qfnra", "default", "cube_and_conquer"]

    def __init__(
        self,
        timeout_ms: int = 10000,
        fast_timeout_ms: int = 100,
        max_workers: int | None = None,
    ) -> None:
        self._timeout_ms = timeout_ms
        self._fast_timeout_ms = fast_timeout_ms
        self._available_tactics = self._get_available_tactics()
        self._max_workers = max_workers or min(len(self._available_tactics), os.cpu_count() or 2)

    def _get_available_tactics(self) -> list[str]:
        """Check which tactics are actually available in the installed Z3 build."""
        available: list[str] = []
        for tactic in self.TACTICS:
            if tactic == "cube_and_conquer":
                try:
                    goal = z3.Goal()
                    z3.Then("simplify", "propagate-values", "cube")(goal)
                    available.append(tactic)
                except z3.Z3Exception as exc:
                    logger.debug("Skipping unavailable tactic %s: %s", tactic, exc)
            else:
                available.append(tactic)
        return available

    def check_hard(self, constraints: list[z3.BoolRef]) -> SolverResult:
        smt_str = self._serialize_constraints(constraints)
        if smt_str is None:
            return SolverResult.unknown()

        ctx = mp.get_context("spawn")
        out_queue: MpQueue[tuple[str, str]] = ctx.Queue()
        processes: list[BaseProcess] = []

        for tactic in self._available_tactics[: self._max_workers]:
            p = ctx.Process(
                target=_portfolio_worker,
                args=(smt_str, tactic, self._timeout_ms, out_queue),
                daemon=True,
            )
            p.start()
            processes.append(p)

        result = SolverResult.unknown()
        start_time = time.time()
        timeout_sec = self._timeout_ms / 1000.0

        finished_workers = 0
        while finished_workers < len(processes):
            remaining_time = timeout_sec - (time.time() - start_time)
            if remaining_time <= 0:
                break
            try:
                status, tactic = out_queue.get(timeout=remaining_time)
                finished_workers += 1
                if status == "sat":
                    result = self._materialize_sat_result(constraints)
                    break
                elif status == "unsat":
                    result = SolverResult.unsat()
                    break
            except queue.Empty:
                break

        for p in processes:
            if p.is_alive():
                p.terminate()
                p.join(timeout=0.1)

        return result

    def _serialize_constraints(self, constraints: list[z3.BoolRef]) -> str | None:
        try:
            solver = z3.Solver()
            solver.add(constraints)
            return solver.to_smt2()
        except (z3.Z3Exception, TypeError):
            return None

    def _materialize_sat_result(self, constraints: list[z3.BoolRef]) -> SolverResult:
        solver = z3.Solver()
        solver.set("timeout", self._timeout_ms)
        solver.add(constraints)
        result = solver.check()
        if result == z3.sat:
            return SolverResult.sat(solver.model())
        return SolverResult.unknown()


def _portfolio_worker(
    smt_str: str, tactic_name: str, timeout_ms: int, out_queue: MpQueue[tuple[str, str]]
) -> None:
    """Isolated worker function for portfolio solving, enabling forceful termination."""
    try:
        import z3

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.from_string(smt_str)

        if tactic_name == "cube_and_conquer":
            try:
                goal = z3.Goal()
                for a in solver.assertions():
                    goal.add(cast("z3.BoolRef", a))
                cube_tactic = z3.Then("simplify", "propagate-values", "cube")
                subgoals = cube_tactic(goal)
            except z3.Z3Exception:
                res = solver.check()
                status = "sat" if res == z3.sat else "unsat" if res == z3.unsat else "unknown"
                out_queue.put((status, tactic_name))
                return

            if len(subgoals) <= 1:
                res = solver.check()
                status = "sat" if res == z3.sat else "unsat" if res == z3.unsat else "unknown"
            else:
                import concurrent.futures
                import os

                is_sat = False
                any_unknown = False

                def check_cube(cube: z3.Goal) -> z3.CheckSatResult:
                    sub_solver = z3.Solver()
                    sub_solver.set("timeout", timeout_ms)
                    sub_solver.add(cube.as_expr())
                    return sub_solver.check()

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=os.cpu_count() or 4
                ) as executor:
                    futures: list[concurrent.futures.Future[z3.CheckSatResult]] = [
                        executor.submit(check_cube, cube) for cube in subgoals
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            sub_res = future.result()
                            if sub_res == z3.sat:
                                is_sat = True
                                for f in futures:
                                    f.cancel()
                                break
                            elif sub_res == z3.unknown:
                                any_unknown = True
                        except Exception:
                            any_unknown = True

                if is_sat:
                    status = "sat"
                elif any_unknown:
                    status = "unknown"
                else:
                    status = "unsat"

            out_queue.put((status, tactic_name))
            return

        elif tactic_name != "default":
            tactic = z3.Tactic(tactic_name)
            goal = z3.Goal()
            for a in solver.assertions():
                goal.add(cast("z3.BoolRef", a))
            try:
                res_goals = tactic(goal)
                sub_solver = z3.Solver()
                sub_solver.set("timeout", timeout_ms)
                for r in res_goals:
                    sub_solver.add(r.as_expr())
                res = sub_solver.check()
            except z3.Z3Exception:
                res = z3.unknown
        else:
            res = solver.check()

        status = "sat" if res == z3.sat else "unsat" if res == z3.unsat else "unknown"
        out_queue.put((status, tactic_name))

    except Exception as exc:
        logger.error("Portfolio solver worker error for tactic %s: %s", tactic_name, exc)
        out_queue.put(("error", tactic_name))


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
    """Check if a list of constraints is satisfiable.

    When an IncrementalSolver is active (set by the executor), delegates
    to it for much better performance.  Otherwise falls back to a cached
    standalone solver.
    """
    solver = _active_solver_var.get()
    if solver is not None:
        return solver.is_sat(constraints, known_sat_prefix_len=known_sat_prefix_len)
    return _is_satisfiable_cached(constraints)


def _is_satisfiable_cached(constraints: Iterable[z3.BoolRef]) -> bool:
    """Standalone (non-incremental) satisfiability check.

    BUG-011 note: The previous docstring said ``(DISABLED)`` — it was never
    actually disabled, but it was also never cached.  Z3 BoolRef objects are
    not hashable, so ``functools.lru_cache`` cannot be applied directly.

    This function is called only when no ``IncrementalSolver`` context is
    active (e.g., in standalone API usage or tests).  For production scan
    runs the IncrementalSolver path is used instead, which has its own
    structural-hash cache.

    If you are calling ``is_satisfiable()`` in a tight loop without an
    IncrementalSolver context, wrap the call-site with:
        with IncrementalSolver() as solver:
            ...
    """
    solver = z3.Solver()
    solver.set("timeout", 5000)
    solver.add(constraints)
    result = solver.check() == z3.sat
    return result


def get_model(constraints: Iterable[z3.BoolRef] | object) -> z3.ModelRef | None:
    """Get a Z3 model for satisfiable constraints."""
    return _get_model_cached(constraints)


def _get_model_cached(constraints: Iterable[z3.BoolRef] | object) -> z3.ModelRef | None:
    """Standalone (non-incremental) model extraction.

    Not actually cached: z3.BoolRef is unhashable so functools.lru_cache
    cannot be applied.  Use IncrementalSolver for hot paths.
    """
    from pysymex.core.memory.cow import ConstraintChain

    if isinstance(constraints, ConstraintChain):
        constraints = constraints.to_list()

    # Ensure we have a list of BoolRef
    if not isinstance(constraints, (list, tuple)):
        try:
            constraints = list(constraints)  # type: ignore[arg-type]
        except TypeError:
            constraints = []

    solver = z3.Solver()
    solver.set("timeout", 5000)
    solver.add(constraints)  # type: ignore[arg-type]
    if solver.check() == z3.sat:
        return solver.model()
    return None


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Get a model string for satisfiable constraints."""
    model = get_model(constraints)
    return str(model) if model else None


def prove(claim: z3.BoolRef) -> bool:
    """Prove that a claim is always true.

    Uses a fresh solver per call (no cache) because z3.BoolRef is
    unhashable.  For repeated validity checks prefer IncrementalSolver.
    """
    solver = z3.Solver()
    solver.set("timeout", 5000)
    solver.add(z3.Not(claim))
    result = solver.check() == z3.unsat
    return result


def clear_solver_caches() -> None:
    """Clear all Z3 solver caches to release context memory.

    Call this between analysis runs (e.g., when scanning multiple files)
    to prevent unbounded memory growth from cached Z3 expressions.
    """
    for cached_fn in _SOLVER_CACHES:
        cached_fn.clear()
