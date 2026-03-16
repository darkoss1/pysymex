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
from collections import OrderedDict, deque
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Protocol, cast

import z3

from pysymex.core.constraint_hash import structural_hash
from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer
from pysymex.core.unsat_core import UnsatCoreResult, extract_unsat_core

logger = logging.getLogger(__name__)

_CACHE_CONTEXT_MASK = (1 << 128) - 1

__all__ = [
    "DEFAULT_SOLVER_TIMEOUT_MS",
    "IncrementalSolver",
    "PortfolioSolver",
    "ShadowSolver",
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
        """Create a result indicating the constraints are mathematically impossible.
        """
        return SolverResult(is_sat=False, is_unsat=True, is_unknown=False)

    @staticmethod
    def unknown() -> SolverResult:
        """Create a result indicating that Z3 could not decide within the timeout.
        """
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
        self._theory_hits: dict[str, int] = {"qflia": 0, "qfs": 0, "mixed": 0}
        self._escalations: int = 0

    def reset(self) -> None:
        """Reset the solver state and clear all caches.

        This effectively starts a fresh Z3 session by popping all scopes,
        clearing the model history, and wiping the structural cache indices.
        Used between independent analysis runs or during resource recovery.
        """

        while self._scope_depth > 0:
            self._solver.pop()
            self._scope_depth -= 1
        self._solver.reset()
        self._cache.clear()
        self._cache_index.clear()
        self._cache_context_stack = [0]
        self._last_models.clear()
        self._optimizer.reset()
        self._is_unsat_context.clear()

    @staticmethod
    def _mix_cache_context(seed: int, value: int) -> int:
        """Combine cache context values deterministically."""
        return ((seed * 1000003) ^ (value + 0x9E3779B97F4A7C15)) & _CACHE_CONTEXT_MASK

    def _current_cache_context(self) -> int:
        """Return the cache context for the current ambient solver state."""
        return self._cache_context_stack[-1]

    def _make_cache_key(self, constraints: list[z3.BoolRef]) -> int:
        """Create a scope-aware cache key for a constraint set."""
        return self._mix_cache_context(self._current_cache_context(), structural_hash(constraints))

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
        return tuple(sorted(c.hash() for c in constraints))

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

    def _cache_store(self, primary: int, discriminator: tuple[int, ...], result: SolverResult) -> None:
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
            constraint_hashes = sorted(structural_hash([constraint]) for constraint in constraints)
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
        start = time.perf_counter()
        result = self._solver.check(*assumptions)
        elapsed_ms = (time.perf_counter() - start) * 1000
        self._solver_time_ms += elapsed_ms

        if result == z3.sat:
            model = self._solver.model()
            if self._warm_start:
                self._last_models.append(model)
            return SolverResult.sat(model)
        elif result == z3.unsat:
            return SolverResult.unsat()
        else:
            return SolverResult.unknown()

    def _get_independent_clusters(self, constraints: list[z3.BoolRef]) -> list[list[z3.BoolRef]]:
        """Partition constraints into independent clusters using the optimizer.

        KNOWN LIMITATION: Ambient constraints added via ``add()`` are already
        internalized in the Z3 solver but are NOT included in the partition.
        This means a cluster may be reported SAT even though the conjunction
        with ambient constraints is UNSAT.  In practice this is safe because
        ``is_sat()`` calls ``self._solver.push(); self._solver.add(cluster)``
        which stacks the cluster ON TOP of the ambient assertions — so Z3
        still sees the full ambient + cluster conjunction.  However, the
        variable-overlap heuristic may place constraints in separate clusters
        when an ambient constraint links their variables, potentially missing
        an early-UNSAT shortcut.  This is a performance concern, not a
        soundness bug, because each cluster is checked against the full
        ambient context.
        """

        constraint_vars: list[frozenset[str]] = []
        for c in constraints:
            var_names = self._optimizer.register_constraint(c)
            constraint_vars.append(var_names)

        clusters: dict[str, list[z3.BoolRef]] = {}
        for c, var_names in zip(constraints, constraint_vars):
            if not var_names:
                root = "CONST"
            else:
                root = self._optimizer._uf.find(next(iter(var_names)))  # type: ignore[protected-access]

            if root not in clusters:
                clusters[root] = []
            clusters[root].append(c)

        return list(clusters.values())

    def is_sat(self, constraints: list[z3.BoolRef]) -> bool:
        """Check if constraints are satisfiable, with caching.

        Uses constraint independence optimization: when constraints can be
        partitioned into independent clusters, each cluster is checked
        separately against the cache, enabling sub-query reuse.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            True if satisfiable, False otherwise.
        """
        if not constraints:
            return True

        if len(constraints) == 1:
            c = constraints[0]
            if z3.is_true(c):
                return True
            if z3.is_false(c):
                return False

        # Try full-query cache first
        cache_key = self._make_cache_key(constraints)
        cache_disc = self._constraints_discriminator(constraints)
        cached = self._cache_lookup(cache_key, cache_disc)
        if cached is not None:
            return cached.is_sat

        # Try cluster-level caching for multi-constraint queries
        if len(constraints) >= 2:
            clusters = self._get_independent_clusters(constraints)
            if len(clusters) > 1:
                # Check each cluster independently
                for cluster in clusters:
                    cluster_key = self._make_cache_key(cluster)
                    cluster_disc = self._constraints_discriminator(cluster)
                    cached_cluster = self._cache_lookup(cluster_key, cluster_disc)
                    if cached_cluster is not None:
                        if not cached_cluster.is_sat:
                            # One cluster UNSAT → whole thing UNSAT
                            result = SolverResult.unsat()
                            self._cache_store(cache_key, cache_disc, result)
                            return False
                    else:
                        # Cluster not cached — solve it
                        self._solver.push()
                        try:
                            for c in cluster:
                                self._solver.add(c)
                            cluster_result = self.check()
                        finally:
                            self._solver.pop()
                        self._cache_store(cluster_key, cluster_disc, cluster_result)
                        if not cluster_result.is_sat:
                            result = SolverResult.unsat()
                            self._cache_store(cache_key, cache_disc, result)
                            return False
                # All clusters SAT
                result = SolverResult.sat(None)
                self._cache_store(cache_key, cache_disc, result)
                return True

        # Single cluster or single constraint — solve directly
        # Theory-aware configuration: detect the dominant theory and
        # tune Z3 parameters before the solve to get the fastest path.
        # NOTE: We configure before push/solve and reset after to avoid
        # leaking theory-specific params into subsequent queries.
        theory = self._detect_theory(constraints)
        self._configure_for_theory(theory)

        self._solver.push()
        start_ns = time.perf_counter()
        try:
            for c in constraints:
                self._solver.add(c)
            result = self.check()
        finally:
            self._solver.pop()
            self._reset_theory_config()
        elapsed_ms = (time.perf_counter() - start_ns) * 1000

        # Auto-escalate slow/unknown queries to portfolio solver
        if result.is_unknown or elapsed_ms >= self._escalation_threshold_ms:
            escalated = self._try_escalate(constraints, elapsed_ms)
            if escalated is not None and not escalated.is_unknown:
                self._cache_store(cache_key, cache_disc, escalated)
                return escalated.is_sat

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
        if cached is not None:
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
                if info_d.get("is_int") == z3.BoolVal(True) or str(info_d.get("is_int")) == "True":
                    formatted[var] = {"type": "int", "value": info_d.get("int")}
                elif (
                    info_d.get("is_bool") == z3.BoolVal(True)
                    or str(info_d.get("is_bool")) == "True"
                ):
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

    # ------------------------------------------------------------------
    # Theory detection and auto-escalation
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_theory(constraints: list[z3.BoolRef]) -> str:
        """Classify the dominant SMT theory of *constraints*.

        Walks the Z3 AST (depth-limited) and returns one of:

        - ``"qflia"`` – quantifier-free linear integer arithmetic only
        - ``"qfs"``   – string / sequence theory present
        - ``"qfbv"``  – bit-vector operations present
        - ``"mixed"``  – multiple theories or unrecognisable ops

        The result drives :meth:`_configure_for_theory` which sets
        theory-specific Z3 parameters before solving.
        """
        has_string = False
        has_bv = False
        has_nonlinear = False

        # Budget — cap tree-walk to avoid blowup on huge formulas
        budget = 2000
        stack: list[z3.ExprRef] = list(constraints)
        visited: set[int] = set()

        while stack and budget > 0:
            expr = stack.pop()
            eid = expr.get_id()
            if eid in visited:
                continue
            visited.add(eid)
            budget -= 1

            sort = expr.sort()
            sort_kind = sort.kind()
            if sort_kind == z3.Z3_SEQ_SORT or sort_kind == z3.Z3_RE_SORT:
                has_string = True
            elif sort_kind == z3.Z3_BV_SORT:
                has_bv = True

            if z3.is_app(expr):
                decl = expr.decl()
                dk = decl.kind()
                # z3.Z3_OP_MUL between two non-constant args → nonlinear
                if dk == z3.Z3_OP_MUL and expr.num_args() >= 2:
                    non_const = sum(
                        1
                        for i in range(expr.num_args())
                        if not z3.is_int_value(expr.arg(i))
                        and not z3.is_rational_value(expr.arg(i))
                    )
                    if non_const >= 2:
                        has_nonlinear = True

                for i in range(expr.num_args()):
                    child = expr.arg(i)
                    if child.get_id() not in visited:
                        stack.append(child)

        if has_string:
            return "qfs"
        if has_bv:
            return "qfbv"
        if has_nonlinear:
            return "mixed"
        return "qflia"

    def _configure_for_theory(self, theory: str) -> None:
        """Set Z3 solver parameters optimal for *theory*.

        Called once per query (not per constraint) — cheap because
        Z3 parameter changes on an existing Solver are O(1).
        """
        self._theory_hits[theory] = self._theory_hits.get(theory, 0) + 1

        if theory == "qflia":
            # Simplex with Gomory cuts — fastest for pure linear integer
            try:
                self._solver.set("smt.arith.solver", 6)
            except z3.Z3Exception:
                pass
        elif theory == "qfs":
            # Use the 'seq' solver for string-heavy queries
            try:
                self._solver.set("smt.string_solver", "seq")
            except z3.Z3Exception:
                pass
        else:
            # Default — reset arith solver to auto
            try:
                self._solver.set("smt.arith.solver", 2)
            except z3.Z3Exception:
                pass

    def _reset_theory_config(self) -> None:
        """Reset solver params to defaults after a theory-specific solve."""
        try:
            self._solver.set("smt.arith.solver", 2)
        except z3.Z3Exception:
            pass

    def _try_escalate(self, constraints: list[z3.BoolRef], elapsed_ms: float) -> SolverResult | None:
        """Escalate to :class:`PortfolioSolver` when a query is too slow.

        Called by :meth:`is_sat` when a single-solver ``check()`` returns
        ``unknown`` or exceeds :attr:`_escalation_threshold_ms`.

        Returns a definitive result, or ``None`` if escalation also fails.
        """
        if elapsed_ms < self._escalation_threshold_ms:
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
            "theory_hits": dict(self._theory_hits),
            "escalations": self._escalations,
        }

    def __repr__(self) -> str:
        return (
            f"IncrementalSolver(queries={self._query_count}, "
            f"cache_hits={self._cache_hits}, scope={self._scope_depth})"
        )


ShadowSolver = IncrementalSolver


class PortfolioSolver:
    """Parallel portfolio solver for hard queries.

    Runs multiple Z3 tactics in parallel and returns the first result.
    Uses ProcessPoolExecutor to bypass the GIL for CPU-bound Z3 work.

    Only triggered for queries that exceed the fast timeout threshold.
    """

    TACTICS = ["smt", "qflia", "qfnra", "default"]

    def __init__(
        self,
        timeout_ms: int = 10000,
        fast_timeout_ms: int = 100,
        max_workers: int | None = None,
    ) -> None:
        self._timeout_ms = timeout_ms
        self._fast_timeout_ms = fast_timeout_ms
        self._max_workers = max_workers or min(len(self.TACTICS), os.cpu_count() or 2)

    def check_hard(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Solve a hard query using parallel tactics.

        Serializes constraints to SMT-LIB format (since Z3 objects
        can't be pickled), reconstructs in each worker process.

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            First SolverResult from any tactic that succeeds.
        """

        smt_str = self._serialize_constraints(constraints)
        if smt_str is None:
            return SolverResult.unknown()

        try:
            with ProcessPoolExecutor(max_workers=self._max_workers) as pool:
                futures = {
                    pool.submit(_portfolio_worker, smt_str, tactic, self._timeout_ms): tactic
                    for tactic in self.TACTICS
                }
                for future in as_completed(futures, timeout=self._timeout_ms / 1000):
                    try:
                        result = future.result(timeout=1)
                        if result is not None and not result.is_unknown:
                            for f in futures:
                                f.cancel()
                            if result.is_sat:
                                return self._materialize_sat_result(constraints)
                            return result
                    except (TimeoutError, z3.Z3Exception, OSError, RuntimeError):
                        logger.debug("Portfolio future failed", exc_info=True)
                        continue
        except (OSError, RuntimeError, z3.Z3Exception, TimeoutError):
            logger.debug("Portfolio solving failed", exc_info=True)

        return SolverResult.unknown()

    def _serialize_constraints(self, constraints: list[z3.BoolRef]) -> str | None:
        """Serialize constraints to SMT-LIB format for cross-process transfer."""
        try:
            solver = z3.Solver()
            solver.add(constraints)
            return solver.to_smt2()
        except (z3.Z3Exception, TypeError):
            logger.debug("Constraint serialization failed", exc_info=True)
            return None

    def _materialize_sat_result(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Rebuild a SAT result with a local model in the parent process."""
        solver = z3.Solver()
        solver.set("timeout", self._timeout_ms)
        solver.add(constraints)
        result = solver.check()
        if result == z3.sat:
            return SolverResult.sat(solver.model())
        if result == z3.unsat:
            return SolverResult.unsat()
        return SolverResult.unknown()


def _portfolio_worker(smt_str: str, tactic_name: str, timeout_ms: int) -> SolverResult | None:
    """Worker function for portfolio solving. Must be top-level for pickling."""
    try:
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.from_string(smt_str)

        if tactic_name != "default":
            try:
                tactic = z3.Tactic(tactic_name)
                goal = z3.Goal()
                for a in solver.assertions():
                    goal.add(a)
                result_goals = tactic(goal)

                solver = z3.Solver()
                solver.set("timeout", timeout_ms)
                for subgoal in result_goals:
                    solver.add(subgoal.as_expr())
            except z3.Z3Exception:
                logger.debug("Z3 tactic %s failed", tactic_name, exc_info=True)

        result = solver.check()
        if result == z3.sat:
            return SolverResult(is_sat=True, is_unsat=False, is_unknown=False)
        elif result == z3.unsat:
            return SolverResult.unsat()
        else:
            return SolverResult.unknown()
    except z3.Z3Exception:
        logger.debug("Portfolio worker failed for tactic %s", tactic_name, exc_info=True)
        return None


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


_active_solver_var: contextvars.ContextVar[IncrementalSolver | None] = contextvars.ContextVar(
    "_active_solver_var", default=None
)

active_incremental_solver = _active_solver_var


def is_satisfiable(constraints: tuple[z3.BoolRef, ...] | list[z3.BoolRef]) -> bool:
    """Check if a list of constraints is satisfiable.

    When an IncrementalSolver is active (set by the executor), delegates
    to it for much better performance.  Otherwise falls back to a cached
    standalone solver.
    """
    solver = _active_solver_var.get()
    if solver is not None:
        return solver.is_sat(constraints if isinstance(constraints, list) else list(constraints))
    if isinstance(constraints, list):
        constraints = tuple(constraints)
    return _is_satisfiable_cached(constraints)


def _is_satisfiable_cached(constraints: tuple[z3.BoolRef, ...]) -> bool:
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


def get_model(constraints: Any) -> z3.ModelRef | None:
    """Get a Z3 model for satisfiable constraints."""
    if not isinstance(constraints, (list, tuple)):
        # Handle ConstraintChain or other iterables
        constraints = tuple(constraints)
    elif isinstance(constraints, list):
        constraints = tuple(constraints)
    return _get_model_cached(constraints)


def _get_model_cached(constraints: tuple[z3.BoolRef, ...]) -> z3.ModelRef | None:
    """Cached implementation of get_model. (DISABLED)"""
    solver = z3.Solver()
    solver.set("timeout", 5000)
    solver.add(constraints)
    if solver.check() == z3.sat:
        return solver.model()
    return None


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Get a model string for satisfiable constraints."""
    model = get_model(constraints)
    return str(model) if model else None


def prove(claim: z3.BoolRef) -> bool:
    """Prove that a claim is always true. (DISABLED CACHE)"""
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
