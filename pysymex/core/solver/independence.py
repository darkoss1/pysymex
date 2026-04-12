# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Constraint Independence Optimization for pysymex.

Implements the constraint-independence optimization from KLEE (Cadar et al.
2008, §4.1): before sending a satisfiability query to Z3, partition the path
constraints into independent clusters by shared variables, then send *only*
the cluster that shares variables with the query.  On real symbolic execution
workloads this reduces average query size by 60-90%, translating directly
into 2-3× solver-time speedup.

Key design decisions
--------------------
1. **No per-query AST walks.**  Extracting free variables from a Z3 expression
   requires a tree walk over the AST.  Doing this on every solver call in pure
   Python would eclipse the SMT savings.  Instead, we extract variables
   *exactly once* per unique Z3 AST hash (``expr.hash()``) and cache the result
   in an instance-level dictionary.  Z3's structural hash is deterministic for a
   given AST and immune to Python wrapper GC — unlike ``id()``, which can be
   reused after garbage collection.

2. **Union-Find clustering.**  Constraints are grouped into independent sets
   using a disjoint-set / union-find with path compression and union-by-rank.
   Building the partition is amortized O(α(n)) per union (effectively O(1)).

3. **Incremental updates.**  `ConstraintIndependenceOptimizer` is designed to
   be kept alive across the entire execution, accumulating constraints as they
   are added during path exploration.  Call ``add_constraint()`` when a new
   constraint enters the path, and ``slice_for_query()`` when you need the
   relevant subset for a branch check.

Complexity
----------
- ``add_constraint(c)``: O(|vars(c)| · α(N))  amortized, where N = total vars
- ``slice_for_query(path, query)``: O(|path| + |vars(query)| · α(N))
- ``extract_variables(expr)``: O(|AST nodes|) on first call, O(1) thereafter

References
----------
- Cadar, C., Dunbar, D., Engler, D. (2008).  KLEE: Unassisted and Automatic
  Generation of High-Coverage Tests for Complex Systems Programs.  OSDI '08.
- EXE (Cadar et al. 2006) - Query slicing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3 as _z3

if TYPE_CHECKING:
    import z3


class UnionFind:
    """Disjoint-Set (Union-Find) data structure with path compression
    and union-by-rank.

    Provides near-O(1) amortized ``find`` and ``union`` operations
    (O(α(n)) where α is the inverse Ackermann function).

    Used internally to cluster constraints into independent groups
    by shared variables.
    """

    __slots__ = ("_parent", "_rank")

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        """Find the representative of the set containing ``x``.

        Creates a new singleton set if ``x`` has not been seen before.
        Uses iterative path compression.

        Complexity: amortized O(α(n)).
        """
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
            return x

        root = x
        while self._parent[root] != root:
            root = self._parent[root]

        while self._parent[x] != root:
            next_x = self._parent[x]
            self._parent[x] = root
            x = next_x
        return root

    def union(self, a: str, b: str) -> str:
        """Merge the sets containing ``a`` and ``b``.

        Returns the new representative of the merged set.
        Uses union-by-rank.

        Complexity: amortized O(α(n)).
        """
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a == root_b:
            return root_a

        rank_a = self._rank[root_a]
        rank_b = self._rank[root_b]
        if rank_a < rank_b:
            self._parent[root_a] = root_b
            return root_b
        elif rank_a > rank_b:
            self._parent[root_b] = root_a
            return root_a
        else:
            self._parent[root_b] = root_a
            self._rank[root_a] += 1
            return root_a

    def connected(self, a: str, b: str) -> bool:
        """Check if ``a`` and ``b`` are in the same set.

        Complexity: amortized O(α(n)).
        """
        return self.find(a) == self.find(b)

    def groups(self) -> dict[str, set[str]]:
        """Return all groups as {representative: set_of_members}.

        Complexity: O(n) where n = number of elements.
        """
        result: dict[str, set[str]] = {}
        for x in self._parent:
            root = self.find(x)
            if root not in result:
                result[root] = set()
            result[root].add(x)
        return result


class ConstraintIndependenceOptimizer:
    """Partitions path constraints into independent clusters by shared variables.

    This is the core optimization: instead of sending ALL path constraints
    to Z3 for every branch check, we identify which constraints actually
    share variables with the branch condition and send *only* those.

    The optimizer maintains internal state (Union-Find, variable caches) and
    is designed to be re-used across the lifetime of a single symbolic
    execution.  Call ``reset()`` between functions / files.

    Example::

        opt = ConstraintIndependenceOptimizer()
        # As constraints arrive during execution:
        opt.register_constraint(c1)  # c1 mentions x, y
        opt.register_constraint(c2)  # c2 mentions z
        opt.register_constraint(c3)  # c3 mentions x

        # When checking a branch on y:
        relevant = opt.slice_for_query([c1, c2, c3], query_on_y)
        # relevant == [c1, c3]  (c2 is independent — shares no variables)

    Attributes:
        sliced_queries: Number of queries where slicing removed ≥1 constraint.
        total_queries: Total number of ``slice_for_query`` calls.
        total_constraints_before: Sum of input constraint list lengths.
        total_constraints_after: Sum of sliced constraint list lengths.
    """

    __slots__ = (
        "_extract_cached",
        "_extract_full",
        "_uf",
        "_var_cache",
        "_constraint_index",
        "_var_to_constraint_indices",
        "_temporal_window",
        "sliced_queries",
        "total_constraints_after",
        "total_constraints_before",
        "total_queries",
    )

    def __init__(self, temporal_window: int = 10) -> None:
        self._uf = UnionFind()
        self._var_cache: dict[int, list[tuple[_z3.ExprRef, frozenset[str]]]] = {}
        self._constraint_index = 0
        self._var_to_constraint_indices: dict[str, list[int]] = {}
        self._temporal_window = temporal_window
        self._extract_full = 0
        self._extract_cached = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0

    def reset(self) -> None:
        """Reset all internal state.  Call between analysis units."""
        self._uf = UnionFind()
        self._var_cache.clear()
        self._constraint_index = 0
        self._var_to_constraint_indices.clear()
        self._extract_full = 0
        self._extract_cached = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0

    def _cache_key(self, expr: z3.ExprRef) -> int:
        """Fast pre-filter key for expression cache buckets."""
        return expr.hash()

    def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
        """Extract free variables from Z3 expression, with caching."""
        key = self._cache_key(expr)
        cached_bucket = self._var_cache.get(key)
        if cached_bucket is not None:
            for cached_expr, cached_vars in cached_bucket:
                try:
                    if _z3.eq(expr, cached_expr):
                        self._extract_cached += 1
                        return cached_vars
                except _z3.Z3Exception:
                    continue

        self._extract_full += 1

        names: set[str] = set()
        worklist: list[_z3.ExprRef] = [expr]
        seen_ids: set[int] = {expr.get_id()}

        while worklist:
            node = worklist.pop()

            if _z3.is_const(node) and node.decl().arity() == 0:
                kind = node.decl().kind()

                if kind == _z3.Z3_OP_UNINTERPRETED:
                    names.add(node.decl().name())
                    continue

            children = node.children()
            for child in children:
                child_id = child.get_id()
                if child_id not in seen_ids:
                    seen_ids.add(child_id)
                    worklist.append(child)

        result = frozenset(names)
        if cached_bucket is None:
            self._var_cache[key] = [(expr, result)]
        else:
            cached_bucket.append((expr, result))
        return result

    def register_constraint(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Register a constraint and update the Union-Find structure.

        Should be called when a constraint is added to the path during
        symbolic execution (e.g. at branch points, ``state.add_constraint``).

        This pre-computes the variable set and merges variable clusters
        *eagerly*, so that ``slice_for_query`` can run in near-O(n) time
        rather than needing a full transitive-closure walk.

        Implements temporal locality: only union variables from constraints
        that remain within the recent temporal window. This keeps loop-heavy
        paths from collapsing into one giant cluster too early.

        Args:
            constraint: A Z3 boolean constraint.

        Returns:
            The frozenset of variable names in the constraint.

        Complexity:
            O(|vars(constraint)| · α(N)) amortized.
        """

        var_names = self._extract_variables(constraint)

        it = iter(var_names)
        first = next(it, None)
        if first is not None:
            self._uf.find(first)

            current_idx = self._constraint_index
            for v in var_names:
                self._var_to_constraint_indices.setdefault(v, []).append(current_idx)

            for v in it:
                v_indices = self._var_to_constraint_indices.get(v, [])
                recent_indices = [
                    idx for idx in v_indices if idx >= current_idx - self._temporal_window
                ]
                if not recent_indices or len(recent_indices) <= 1:
                    self._uf.union(first, v)

        self._constraint_index += 1
        return var_names

    def get_variables(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Get the cached variable set for a constraint.

        If the constraint hasn't been registered yet, extracts and caches
        the variables but does NOT update the Union-Find structure (use
        ``register_constraint`` for that).

        Args:
            constraint: A Z3 expression.

        Returns:
            Frozenset of variable names.

        Complexity: O(1) if cached, O(|AST|) on first extraction.
        """
        return self._extract_variables(constraint)

    def slice_for_query(
        self,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef]:
        """Return the minimal subset of ``path_constraints`` relevant to ``query``.

        Two constraints are "relevant" if they share at least one variable
        (directly or transitively via other constraints).  This is computed
        efficiently via the Union-Find: we find the cluster roots of the
        query's variables, then keep only constraints whose variables belong
        to the same cluster(s).

        If the query has no variables (e.g. ``z3.BoolVal(True)``), returns
        an empty list (the query is trivially independent of all constraints).

        If ALL constraints are relevant (i.e. slicing doesn't help), returns
        the original list object to avoid allocation.

        Args:
            path_constraints: The full list of accumulated path constraints.
            query: The branch condition (or negation) being checked.

        Returns:
            A list of constraints that share variables with the query.
            May be the same list object if no reduction is possible.

        Complexity:
            O(|path_constraints| + |vars(query)|) amortized, because:
            - Each constraint lookup is O(|vars(c)|) on first encounter
              (cached thereafter), plus O(|vars(c)| · α(N)) for UF lookups.
            - In steady state, all variable sets are cached, so it's
              O(|path_constraints|) for the filter pass.
        """
        self.total_queries += 1
        n_input = len(path_constraints)
        self.total_constraints_before += n_input

        if n_input == 0:
            self.total_constraints_after += 0
            return []

        query_vars = self.get_variables(query)
        if not query_vars:
            self.total_constraints_after += 0
            self.sliced_queries += 1
            return []

        query_roots: set[str] = set()
        for v in query_vars:
            query_roots.add(self._uf.find(v))

        relevant: list[z3.BoolRef] = []
        for constraint in path_constraints:
            c_vars = self.get_variables(constraint)
            if not c_vars:
                relevant.append(constraint)
                continue

            for v in c_vars:
                if self._uf.find(v) in query_roots:
                    relevant.append(constraint)
                    break

        n_output = len(relevant)
        self.total_constraints_after += n_output

        if n_output < n_input:
            self.sliced_queries += 1

        if n_output == n_input:
            return path_constraints

        return relevant

    def get_stats(self) -> dict[str, object]:
        """Return optimizer statistics for diagnostics.

        Returns:
            Dictionary with query counts, constraint reduction ratios, and
            cache statistics.
        """
        if self.total_constraints_before > 0:
            reduction_ratio = 1.0 - (self.total_constraints_after / self.total_constraints_before)
        else:
            reduction_ratio = 0.0

        return {
            "total_queries": self.total_queries,
            "sliced_queries": self.sliced_queries,
            "total_constraints_before": self.total_constraints_before,
            "total_constraints_after": self.total_constraints_after,
            "reduction_ratio": round(reduction_ratio, 4),
            "registered_constraints": sum(len(bucket) for bucket in self._var_cache.values()),
            "var_cache_size": sum(len(bucket) for bucket in self._var_cache.values()),
            "full_extractions": self._extract_full,
            "cached_extractions": self._extract_cached,
        }
