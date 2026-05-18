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

from collections import OrderedDict
from typing import Protocol, TypeGuard

import z3
import z3 as _z3
from pysymex.core.types.base import safe_z3_eq


class Z3Convertible(Protocol):
    """Protocol for symbolic objects that can expose a Z3 expression."""

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 expression represented by this object."""
        raise TypeError("Protocol method Z3Convertible.to_z3() is not callable at runtime")


def has_to_z3(value: object) -> TypeGuard[Z3Convertible]:
    """Return True when a value has a callable to_z3 method."""
    return hasattr(value, "to_z3") and callable(getattr(value, "to_z3", None))


_Z3Convertible = Z3Convertible
_has_to_z3 = has_to_z3


def _decl_dependency_token(decl: z3.FuncDeclRef) -> str:
    """Return a stable dependency token for an uninterpreted function declaration."""
    domain = ",".join(str(decl.domain(i)) for i in range(decl.arity()))
    return f"uf:{decl.name()}({domain})->{decl.range()}"


def _expr_theory_signature(expr: z3.ExprRef) -> tuple[str, ...]:
    """Return a compact theory/sort signature for a Z3 expression."""
    tokens: set[str] = set()
    worklist: list[z3.ExprRef] = [expr]
    seen_ids: set[int] = {expr.get_id()}
    while worklist:
        node = worklist.pop()
        try:
            tokens.add(f"sort:{node.sort()}")
        except z3.Z3Exception:
            tokens.add("sort:<unknown>")
        if z3.is_quantifier(node):
            tokens.add("kind:quantifier_forall" if node.is_forall() else "kind:quantifier_exists")
            body = node.body()
            body_id = body.get_id()
            if body_id not in seen_ids:
                seen_ids.add(body_id)
                worklist.append(body)
            continue
        if not z3.is_app(node):
            tokens.add("kind:non_app")
            continue
        decl = node.decl()
        tokens.add(f"kind:{decl.kind()}")
        if decl.kind() == z3.Z3_OP_UNINTERPRETED:
            tokens.add(_decl_dependency_token(decl))
        for child in node.children():
            child_id = child.get_id()
            if child_id not in seen_ids:
                seen_ids.add(child_id)
                worklist.append(child)
    return tuple(sorted(tokens))


def _as_z3_expr(value: object) -> z3.ExprRef | None:
    """Normalize a Z3 or symbolic expression candidate."""
    if isinstance(value, z3.ExprRef):
        return value
    if _has_to_z3(value):
        return value.to_z3()
    return None


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
        "_adaptive_disable_min_queries",
        "_adaptive_disable_min_reduction",
        "_extract_cached",
        "_extract_full",
        "_constraint_index",
        "_prefix_theory_signature_cache",
        "_slice_cache",
        "_slice_cache_hits",
        "_slice_cache_max_size",
        "_slice_cache_misses",
        "_slicing_disabled",
        "_slicing_disabled_count",
        "_temporal_window",
        "_theory_signature_cache",
        "_theory_signature_cached",
        "_theory_signature_full",
        "_uf",
        "_var_to_constraint_indices",
        "_var_cache",
        "sliced_queries",
        "total_constraints_after",
        "total_constraints_before",
        "total_queries",
    )

    def __init__(
        self,
        temporal_window: int = 10,
        slice_cache_size: int = 1024,
        adaptive_disable_min_queries: int = 32,
        adaptive_disable_min_reduction: float = 0.02,
    ) -> None:
        self._uf = UnionFind()
        self._var_cache: dict[int, list[tuple[_z3.ExprRef, frozenset[str]]]] = {}
        self._theory_signature_cache: dict[int, list[tuple[_z3.ExprRef, tuple[str, ...]]]] = {}
        self._prefix_theory_signature_cache: dict[tuple[int, ...], frozenset[str]] = {}
        self._slice_cache: OrderedDict[
            int, list[tuple[tuple[z3.BoolRef, ...], z3.BoolRef, tuple[int, ...]]]
        ] = OrderedDict()
        self._constraint_index = 0
        self._var_to_constraint_indices: dict[str, list[int]] = {}
        self._temporal_window = temporal_window
        self._slice_cache_max_size = max(1, slice_cache_size)
        self._adaptive_disable_min_queries = max(1, adaptive_disable_min_queries)
        self._adaptive_disable_min_reduction = max(0.0, adaptive_disable_min_reduction)
        self._extract_full = 0
        self._extract_cached = 0
        self._theory_signature_full = 0
        self._theory_signature_cached = 0
        self._slice_cache_hits = 0
        self._slice_cache_misses = 0
        self._slicing_disabled = False
        self._slicing_disabled_count = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0

    def reset(self) -> None:
        """Reset all internal state.  Call between analysis units."""
        self._uf = UnionFind()
        self._var_cache.clear()
        self._theory_signature_cache.clear()
        self._prefix_theory_signature_cache.clear()
        self._slice_cache.clear()
        self._constraint_index = 0
        self._var_to_constraint_indices.clear()
        self._extract_full = 0
        self._extract_cached = 0
        self._theory_signature_full = 0
        self._theory_signature_cached = 0
        self._slice_cache_hits = 0
        self._slice_cache_misses = 0
        self._slicing_disabled = False
        self._slicing_disabled_count = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0

    def _cache_key(self, expr: z3.ExprRef) -> int:
        """Fast pre-filter key for expression cache buckets."""
        return expr.hash()

    def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
        """Extract free variables from Z3 expression, with caching."""
        z3_expr = _as_z3_expr(expr)
        if z3_expr is None:
            return frozenset()

        key = self._cache_key(z3_expr)
        cached_bucket = self._var_cache.get(key)
        if cached_bucket is not None:
            for cached_expr, cached_vars in cached_bucket:
                try:
                    if z3_expr is cached_expr or safe_z3_eq(z3_expr, cached_expr):
                        self._extract_cached += 1
                        return cached_vars
                except _z3.Z3Exception:
                    continue

        self._extract_full += 1

        names: set[str] = set()
        worklist: list[_z3.ExprRef] = [z3_expr]
        seen_ids: set[int] = {z3_expr.get_id()}

        keepalive: list[_z3.ExprRef] = []

        while worklist:
            node = worklist.pop()
            if _z3.is_quantifier(node):
                body = node.body()
                keepalive.append(body)
                body_id = body.get_id()
                if body_id not in seen_ids:
                    seen_ids.add(body_id)
                    worklist.append(body)
                continue
            if not _z3.is_app(node):
                continue
            decl = node.decl()
            kind = decl.kind()

            if kind == _z3.Z3_OP_UNINTERPRETED:
                if decl.arity() == 0:
                    names.add(decl.name())
                    continue
                names.add(_decl_dependency_token(decl))

            children = node.children()
            if children:
                keepalive.extend(children)
            for child in children:
                child_id = child.get_id()
                if child_id not in seen_ids:
                    seen_ids.add(child_id)
                    worklist.append(child)

        result = frozenset(names)
        if cached_bucket is None:
            self._var_cache[key] = [(z3_expr, result)]
        else:
            cached_bucket.append((z3_expr, result))
        return result

    def register_constraint(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Register a constraint and update the Union-Find structure.

        Should be called when a constraint is added to the path during
        symbolic execution (e.g. at branch points, ``state.add_constraint``).

        This pre-computes the variable set and merges variable clusters
        *eagerly*, so that ``slice_for_query`` can run in near-O(n) time
        rather than needing a full transitive-closure walk.

        Soundness requires dependency closure, so all variables in a constraint
        are unioned. The temporal_window constructor argument is retained for
        API compatibility but does not weaken closure.

        Args:
            constraint: A Z3 boolean constraint.

        Returns:
            The frozenset of variable names in the constraint.

        Complexity:
            O(|vars(constraint)| · α(N)) amortized.
        """

        z3_c = _as_z3_expr(constraint)
        if z3_c is None:
            self._constraint_index += 1
            return frozenset()

        var_names = self._extract_variables(z3_c)

        it = iter(var_names)
        first = next(it, None)
        if first is not None:
            self._uf.find(first)

            current_idx = self._constraint_index
            for v in var_names:
                self._var_to_constraint_indices.setdefault(v, []).append(current_idx)

            for v in it:
                self._uf.union(first, v)

        self._constraint_index += 1
        return var_names

    def find_group_root(self, variable: str) -> str:
        """Return the union-find root for a variable name."""
        return self._uf.find(variable)

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
        z3_c = _as_z3_expr(constraint)
        if z3_c is None:
            return frozenset()
        return self._extract_variables(z3_c)

    def _get_theory_signature(self, expr: z3.ExprRef) -> tuple[str, ...]:
        """Return cached theory/sort signature for a verified Z3 AST."""
        key = self._cache_key(expr)
        cached_bucket = self._theory_signature_cache.get(key)
        if cached_bucket is not None:
            for cached_expr, cached_signature in cached_bucket:
                try:
                    if expr is cached_expr or safe_z3_eq(expr, cached_expr):
                        self._theory_signature_cached += 1
                        return cached_signature
                except _z3.Z3Exception:
                    continue

        self._theory_signature_full += 1
        signature = _expr_theory_signature(expr)
        if cached_bucket is None:
            self._theory_signature_cache[key] = [(expr, signature)]
        else:
            cached_bucket.append((expr, signature))
        return signature

    def _slice_cache_key(
        self,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        query_vars: frozenset[str],
    ) -> int:
        path_hashes = tuple(c.hash() for c in path_constraints)
        prefix_sig = self._prefix_theory_signature_cache.get(path_hashes)
        if prefix_sig is None:
            tokens: set[str] = set()
            for c in path_constraints:
                tokens.update(self._get_theory_signature(c))
            prefix_sig = frozenset(tokens)
            self._prefix_theory_signature_cache[path_hashes] = prefix_sig

        query_sig = self._get_theory_signature(query)
        theory_signature = tuple(sorted(prefix_sig.union(query_sig)))

        return hash(
            (
                len(path_constraints),
                path_hashes,
                query.hash(),
                tuple(sorted(query_vars)),
                theory_signature,
            )
        )

    def _lookup_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef] | None:
        bucket = self._slice_cache.get(cache_key)
        if bucket is None:
            self._slice_cache_misses += 1
            return None

        self._slice_cache.move_to_end(cache_key)
        for cached_path, cached_query, cached_indices in bucket:
            if len(cached_path) != len(path_constraints):
                continue
            try:
                if cached_query is not query and not safe_z3_eq(cached_query, query):
                    continue
                if not all(
                    cached is current or safe_z3_eq(cached, current)
                    for cached, current in zip(cached_path, path_constraints, strict=True)
                ):
                    continue
            except z3.Z3Exception:
                continue
            self._slice_cache_hits += 1
            if len(cached_indices) == len(path_constraints):
                return path_constraints
            return [path_constraints[index] for index in cached_indices]

        self._slice_cache_misses += 1
        return None

    def _store_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
        relevant_indices: tuple[int, ...],
    ) -> None:
        entry = (tuple(path_constraints), query, relevant_indices)
        bucket = self._slice_cache.get(cache_key)
        if bucket is None:
            self._slice_cache[cache_key] = [entry]
        else:
            bucket.append(entry)
            self._slice_cache.move_to_end(cache_key)
        while len(self._slice_cache) > self._slice_cache_max_size:
            self._slice_cache.popitem(last=False)

    def _maybe_disable_slicing(self) -> None:
        if self._slicing_disabled or self.total_queries < self._adaptive_disable_min_queries:
            return
        if self.total_constraints_before <= 0:
            return

        reduction_ratio = 1.0 - (self.total_constraints_after / self.total_constraints_before)
        cache_attempts = self._slice_cache_hits + self._slice_cache_misses
        cache_hit_rate = self._slice_cache_hits / cache_attempts if cache_attempts else 0.0

        if reduction_ratio < self._adaptive_disable_min_reduction and cache_hit_rate < 0.70:
            self._slicing_disabled = True
            self._slicing_disabled_count += 1

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
            self._maybe_disable_slicing()
            return []

        if self._slicing_disabled:
            self.total_constraints_after += n_input
            return path_constraints

        query_vars = self.get_variables(query)
        cache_key = self._slice_cache_key(path_constraints, query, query_vars)
        cached = self._lookup_slice_cache(cache_key, path_constraints, query)
        if cached is not None:
            n_cached = len(cached)
            self.total_constraints_after += n_cached
            if n_cached < n_input:
                self.sliced_queries += 1
            self._maybe_disable_slicing()
            return cached

        if not query_vars:
            self.total_constraints_after += 0
            self.sliced_queries += 1
            self._store_slice_cache(cache_key, path_constraints, query, ())
            self._maybe_disable_slicing()
            return []

        query_roots: set[str] = set()
        uf_find = self._uf.find
        for v in query_vars:
            query_roots.add(uf_find(v))

        relevant_indices: list[int] = []
        root_cache: dict[str, str] = {}
        for index, constraint in enumerate(path_constraints):
            c_vars = self.get_variables(constraint)
            if not c_vars:
                relevant_indices.append(index)
                continue

            for v in c_vars:
                root = root_cache.get(v)
                if root is None:
                    root = uf_find(v)
                    root_cache[v] = root
                if root in query_roots:
                    relevant_indices.append(index)
                    break

        n_output = len(relevant_indices)
        self.total_constraints_after += n_output

        if n_output < n_input:
            self.sliced_queries += 1

        relevant_indices_tuple = tuple(relevant_indices)
        self._store_slice_cache(cache_key, path_constraints, query, relevant_indices_tuple)
        self._maybe_disable_slicing()

        if n_output == n_input:
            return path_constraints

        return [path_constraints[index] for index in relevant_indices]

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
        slice_cache_attempts = self._slice_cache_hits + self._slice_cache_misses
        slice_cache_hit_rate = (
            self._slice_cache_hits / slice_cache_attempts if slice_cache_attempts else 0.0
        )

        return {
            "total_queries": self.total_queries,
            "sliced_queries": self.sliced_queries,
            "total_constraints_before": self.total_constraints_before,
            "total_constraints_after": self.total_constraints_after,
            "reduction_ratio": round(reduction_ratio, 4),
            "slice_cache_hits": self._slice_cache_hits,
            "slice_cache_misses": self._slice_cache_misses,
            "slice_cache_hit_rate": round(slice_cache_hit_rate, 4),
            "slice_cache_size": len(self._slice_cache),
            "slicing_disabled": self._slicing_disabled,
            "slicing_disabled_count": self._slicing_disabled_count,
            "registered_constraints": sum(len(bucket) for bucket in self._var_cache.values()),
            "var_cache_size": sum(len(bucket) for bucket in self._var_cache.values()),
            "full_extractions": self._extract_full,
            "cached_extractions": self._extract_cached,
            "theory_signature_cache_size": sum(
                len(bucket) for bucket in self._theory_signature_cache.values()
            ),
            "theory_signature_full": self._theory_signature_full,
            "theory_signature_cached": self._theory_signature_cached,
        }
