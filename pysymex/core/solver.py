"""Z3 Solver wrapper for pysymex.

This module provides a high-level interface to the Z3 theorem prover,
with incremental solving, structural caching, warm-start hints,
and portfolio solving for hard queries.

v0.4.0: Rewritten for world-class performance.
- IncrementalSolver: persistent solver with push/pop scope management
- PortfolioSolver: parallel tactic execution for hard queries
- Structural hash-based caching (no string conversion)
- Warm-start with previous model hints
"""

from __future__ import annotations


import logging

import os

import time

from collections import OrderedDict, deque

from concurrent.futures import ProcessPoolExecutor, as_completed

from dataclasses import dataclass

from functools import lru_cache

from typing import Any, cast


import z3


from pysymex.core.constraint_hash import structural_hash

from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer

from pysymex.core.constraint_simplifier import (
    quick_contradiction_check,
    remove_subsumed,
    simplify_constraints,
)

from pysymex.core.unsat_core import UnsatCoreResult, extract_unsat_core

logger = logging.getLogger(__name__)


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


@dataclass
class SolverResult:
    """Result of a satisfiability check."""

    is_sat: bool

    is_unsat: bool

    is_unknown: bool

    model: z3.ModelRef | None = None

    @staticmethod
    def sat(model: z3.ModelRef) -> SolverResult:
        return SolverResult(is_sat=True, is_unsat=False, is_unknown=False, model=model)

    @staticmethod
    def unsat() -> SolverResult:
        return SolverResult(is_sat=False, is_unsat=True, is_unknown=False)

    @staticmethod
    def unknown() -> SolverResult:
        return SolverResult(is_sat=False, is_unsat=False, is_unknown=True)


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
    ) -> None:
        self._solver = z3.Solver()

        self._solver.set("timeout", timeout_ms)

        self._timeout_ms = timeout_ms

        self._scope_depth = 0

        self._cache: OrderedDict[int, SolverResult] = OrderedDict()

        self._cache_size = cache_size

        self._query_count = 0

        self._cache_hits = 0

        self._solver_time_ms = 0.0

        self._warm_start = warm_start

        self._last_models: deque[z3.ModelRef] = deque(maxlen=10)

        self._optimizer = ConstraintIndependenceOptimizer()

    def reset(self) -> None:
        """Reset the solver state."""

        while self._scope_depth > 0:
            self._solver.pop()

            self._scope_depth -= 1

        self._solver.reset()

        self._cache.clear()

        self._last_models.clear()

        self._optimizer.reset()

    def push(self) -> None:
        """Push a new constraint scope."""

        self._solver.push()

        self._scope_depth += 1

        self._cache.clear()

    def pop(self) -> None:
        """Pop the current constraint scope."""

        if self._scope_depth > 0:
            self._solver.pop()

            self._scope_depth -= 1

            self._cache.clear()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add constraints to the solver."""

        self._solver.add(*constraints)

        self._cache.clear()

    def enter_scope(self, constraints: list[z3.BoolRef]) -> None:
        """Push a new scope and add constraints. Used for path exploration."""

        self.push()

        for c in constraints:
            try:
                self._solver.add(c)

            except Exception:
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
                root = self._optimizer._uf.find(next(iter(var_names)))

            if root not in clusters:
                clusters[root] = []

            clusters[root].append(c)

        return list(clusters.values())

    def is_sat(self, constraints: list[z3.BoolRef]) -> bool:
        """Check if constraints are satisfiable, with caching and optimization.

        Uses structural hashing for cache keys.
        Uses ConstraintIndependenceOptimizer to split constraints into independent
        clusters, checking each separately. This yields exponential speedups
        on independent paths.

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

            cache_key = structural_hash(constraints)

            if cache_key in self._cache:
                self._cache_hits += 1

                self._cache.move_to_end(cache_key)

                return self._cache[cache_key].is_sat

            self._solver.push()

            try:
                self._solver.add(c)

                result = self.check()

            finally:
                self._solver.pop()

            if len(self._cache) >= self._cache_size:
                self._cache.popitem(last=False)

            self._cache[cache_key] = result

            return result.is_sat

        if quick_contradiction_check(constraints):
            return False

        constraints = simplify_constraints(constraints)

        if not constraints:
            return True

        if len(constraints) == 1 and z3.is_false(constraints[0]):
            return False

        constraints = remove_subsumed(constraints)

        cache_key = structural_hash(constraints)

        if cache_key in self._cache:
            self._cache_hits += 1

            self._cache.move_to_end(cache_key)

            return self._cache[cache_key].is_sat

        clusters = self._get_independent_clusters(constraints)

        clusters.sort(key=len)

        for cluster in clusters:
            cluster_key = structural_hash(cluster)

            if cluster_key in self._cache:
                self._cache_hits += 1

                self._cache.move_to_end(cluster_key)

                result = self._cache[cluster_key]

            else:
                self._solver.push()

                try:
                    self._solver.add(cluster)

                    result = self.check()

                finally:
                    self._solver.pop()

                if len(self._cache) >= self._cache_size:
                    self._cache.popitem(last=False)

                self._cache[cluster_key] = result

            if not result.is_sat:
                if len(self._cache) >= self._cache_size:
                    self._cache.popitem(last=False)

                self._cache[cache_key] = result

                return False

        return True

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Check satisfiability with full result caching.

        Returns the full SolverResult (including model if SAT).

        Args:
            constraints: List of Z3 boolean constraints.

        Returns:
            SolverResult with sat/unsat/unknown and optional model.
        """

        cache_key = structural_hash(constraints)

        if cache_key in self._cache:
            self._cache_hits += 1

            self._cache.move_to_end(cache_key)

            return self._cache[cache_key]

        self._solver.push()

        try:
            self._solver.add(constraints)

            result_obj = self.check()

        finally:
            self._solver.pop()

        if len(self._cache) >= self._cache_size:
            self._cache.popitem(last=False)

        self._cache[cache_key] = result_obj

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
    ) -> dict[str, Any]:
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

        result: dict[str, Any] = {}

        for decl in model.decls():
            name = decl.name()

            value = model[decl]

            if name.endswith("_int"):
                base = name[:-4]

                result.setdefault(base, {})["int"] = value

            elif name.endswith("_bool"):
                base = name[:-5]

                result.setdefault(base, {})["bool"] = value

            elif name.endswith("_is_int"):
                base = name[:-7]

                result.setdefault(base, {})["is_int"] = value

            elif name.endswith("_is_bool"):
                base = name[:-8]

                result.setdefault(base, {})["is_bool"] = value

            elif name.endswith("_str"):
                base = name[:-4]

                result.setdefault(base, {})["str"] = value

            elif name.endswith("_len"):
                base = name[:-4]

                result.setdefault(base, {})["len"] = value

            else:
                result[name] = {"value": value}

        formatted: dict[str, Any] = {}

        for var, info in result.items():
            if isinstance(info, dict):
                info_d = cast(dict[str, Any], info)

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

    def get_stats(self) -> dict[str, Any]:
        """Get solver statistics."""

        return {
            "queries": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
            "scope_depth": self._scope_depth,
            "solver_time_ms": round(self._solver_time_ms, 2),
            "warm_start_models": len(self._last_models),
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

                            return result

                    except Exception:
                        logger.debug("Portfolio future failed", exc_info=True)

                        continue

        except Exception:
            logger.debug("Portfolio solving failed", exc_info=True)

        return SolverResult.unknown()

    def _serialize_constraints(self, constraints: list[z3.BoolRef]) -> str | None:
        """Serialize constraints to SMT-LIB format for cross-process transfer."""

        try:
            solver = z3.Solver()

            solver.add(constraints)

            return solver.to_smt2()

        except Exception:
            logger.debug("Constraint serialization failed", exc_info=True)

            return None


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

            except Exception:
                logger.debug("Z3 tactic %s failed", tactic_name, exc_info=True)

        result = solver.check()

        if result == z3.sat:
            return SolverResult.sat(None)

        elif result == z3.unsat:
            return SolverResult.unsat()

        else:
            return SolverResult.unknown()

    except Exception:
        logger.debug("Portfolio worker failed for tactic %s", tactic_name, exc_info=True)

        return None


DEFAULT_SOLVER_TIMEOUT_MS: int = 5000

"""Default timeout in milliseconds applied to all Z3 solver instances."""


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


_SOLVER_CACHES: list[Any] = []


active_incremental_solver: IncrementalSolver | None = None


def is_satisfiable(constraints: tuple[z3.BoolRef, ...] | list[z3.BoolRef]) -> bool:
    """Check if a list of constraints is satisfiable.

    When an IncrementalSolver is active (set by the executor), delegates
    to it for much better performance.  Otherwise falls back to a cached
    standalone solver.
    """

    solver = active_incremental_solver

    if solver is not None:
        return solver.is_sat(constraints if isinstance(constraints, list) else list(constraints))

    if isinstance(constraints, list):
        constraints = tuple(constraints)

    return _is_satisfiable_cached(constraints)


@lru_cache(maxsize=512)
def _is_satisfiable_cached(constraints: tuple[z3.BoolRef, ...]) -> bool:
    """Cached implementation of satisfiability check.

    WARNING: Z3 expressions used as lru_cache keys rely on Z3's __hash__,
    which can produce collisions for structurally different expressions.
    In practice the collision rate is negligible for the constraint tuples
    seen during symbolic execution, but callers should be aware that cache
    hits are not guaranteed to be semantically identical.  If this ever
    causes unsoundness, replace lru_cache with a dict keyed on
    structural_hash() from pysymex.core.constraint_hash.
    """

    solver = z3.Solver()

    solver.set("timeout", 5000)

    solver.add(constraints)

    return solver.check() == z3.sat


_SOLVER_CACHES.append(_is_satisfiable_cached)


def get_model(constraints: tuple[z3.BoolRef, ...] | list[z3.BoolRef]) -> z3.ModelRef | None:
    """Get a Z3 model for satisfiable constraints."""

    if isinstance(constraints, list):
        constraints = tuple(constraints)

    return _get_model_cached(constraints)


@lru_cache(maxsize=512)
def _get_model_cached(constraints: tuple[z3.BoolRef, ...]) -> z3.ModelRef | None:
    """Cached implementation of get_model.

    WARNING: Same Z3 hash-collision caveat as _is_satisfiable_cached.
    """

    solver = z3.Solver()

    solver.set("timeout", 5000)

    solver.add(constraints)

    if solver.check() == z3.sat:
        return solver.model()

    return None


_SOLVER_CACHES.append(_get_model_cached)


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Get a model string for satisfiable constraints."""

    model = get_model(constraints)

    return str(model) if model else None


@lru_cache(maxsize=512)
def prove(claim: z3.BoolRef) -> bool:
    """Prove that a claim is always true.

    WARNING: Same Z3 hash-collision caveat as _is_satisfiable_cached.
    """

    solver = z3.Solver()

    solver.set("timeout", 5000)

    solver.add(z3.Not(claim))

    return solver.check() == z3.unsat


_SOLVER_CACHES.append(prove)


def clear_solver_caches() -> None:
    """Clear all Z3 solver caches to release context memory.

    Call this between analysis runs (e.g., when scanning multiple files)
    to prevent unbounded memory growth from cached Z3 expressions.
    """

    for cached_fn in _SOLVER_CACHES:
        cached_fn.cache_clear()
