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
        "sliced_queries",
        "total_constraints_after",
        "total_constraints_before",
        "total_queries",
    )

    def __init__(self) -> None:
        self._uf = UnionFind()

        self._var_cache: dict[int, frozenset[str]] = {}

        self._extract_full: int = 0
        self._extract_cached: int = 0
        self.sliced_queries: int = 0
        self.total_queries: int = 0
        self.total_constraints_before: int = 0
        self.total_constraints_after: int = 0

    def reset(self) -> None:
        """Reset all internal state.  Call between analysis units."""
        self._uf = UnionFind()
        self._var_cache.clear()
        self._extract_full = 0
        self._extract_cached = 0
        self.sliced_queries = 0
        self.total_queries = 0
        self.total_constraints_before = 0
        self.total_constraints_after = 0

    def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
        """Extract free variables from Z3 expression, with caching."""
        key = expr.hash()
        cached = self._var_cache.get(key)
        if cached is not None:
            self._extract_cached += 1
            return cached

        self._extract_full += 1

        names: set[str] = set()
        worklist: list[_z3.ExprRef] = [expr]
        seen_ids: set[int] = {key}

        while worklist:
            node = worklist.pop()

            if _z3.is_const(node) and node.decl().arity() == 0:
                kind = node.decl().kind()

                if kind == _z3.Z3_OP_UNINTERPRETED:
                    names.add(node.decl().name())
                    continue

            children = node.children()
            for child in children:
                child_id = child.hash()
                if child_id not in seen_ids:
                    seen_ids.add(child_id)
                    worklist.append(child)

        result = frozenset(names)
        self._var_cache[key] = result
        return result

    def register_constraint(self, constraint: z3.BoolRef) -> frozenset[str]:
        """Register a constraint and update the Union-Find structure.

        Should be called when a constraint is added to the path during
        symbolic execution (e.g. at branch points, ``state.add_constraint``).

        This pre-computes the variable set and merges variable clusters
        *eagerly*, so that ``slice_for_query`` can run in near-O(n) time
        rather than needing a full transitive-closure walk.

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
            for v in it:
                self._uf.union(first, v)

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
            "registered_constraints": len(self._var_cache),
            "var_cache_size": len(self._var_cache),
            "full_extractions": self._extract_full,
            "cached_extractions": self._extract_cached,
        }


def _run_self_tests() -> None:
    """Comprehensive self-test suite demonstrating correctness and performance."""
    import logging
    import time

    import z3 as _z3

    logging.basicConfig(level=logging.WARNING)

    print("=" * 70)
    print("Constraint Independence Optimizer — Self Tests")
    print("=" * 70)

    print("\n[TEST 1] Union-Find basic operations")
    uf = UnionFind()
    assert uf.find("a") == "a"
    assert uf.find("b") == "b"
    assert not uf.connected("a", "b")

    uf.union("a", "b")
    assert uf.connected("a", "b")
    assert not uf.connected("a", "c")

    uf.union("b", "c")
    assert uf.connected("a", "c")

    uf.union("d", "e")
    assert not uf.connected("a", "d")

    uf.union("c", "d")
    assert uf.connected("a", "e")

    groups = uf.groups()
    assert len(groups) == 1, f"Expected 1 group, got {len (groups )}"
    print("  PASS — union, find, path compression, transitivity")

    print("\n[TEST 2] Z3 variable extraction + caching")
    opt = ConstraintIndependenceOptimizer()

    x = _z3.Int("x")
    y = _z3.Int("y")
    z = _z3.Int("z")

    expr1 = x + y > 5
    vars1 = opt.get_variables(expr1)
    assert vars1 == frozenset({"x", "y"}), f"Got {vars1}"

    vars1b = opt.get_variables(expr1)
    assert vars1b == vars1

    expr2 = z < 10
    vars2 = opt.get_variables(expr2)
    assert vars2 == frozenset({"z"})

    expr3 = _z3.And(x > 0, _z3.Or(y < 10, z == 42))
    vars3 = opt.get_variables(expr3)
    assert vars3 == frozenset({"x", "y", "z"}), f"Mismatch! Got {vars3}"

    expr4 = _z3.BoolVal(True)
    vars4 = opt.get_variables(expr4)
    assert vars4 == frozenset()

    expr5 = _z3.IntVal(42) > _z3.IntVal(10)
    vars5 = opt.get_variables(expr5)
    assert vars5 == frozenset()

    stats = opt.get_stats()
    assert stats["full_extractions"] >= 4
    assert stats["cached_extractions"] >= 1
    print(f"  PASS — extraction correct, cache: {stats}")

    print("\n[TEST 3] Constraint slicing — independent clusters")
    opt = ConstraintIndependenceOptimizer()

    a = _z3.Int("a")
    b = _z3.Int("b")
    c = _z3.Int("c")
    d = _z3.Int("d")
    e = _z3.Int("e")

    c1 = a > 0
    c2 = b < 10
    c3 = c + d > 5
    c4 = a + b < 20
    c5 = e == 42

    for ci in [c1, c2, c3, c4, c5]:
        opt.register_constraint(ci)

    query_a = a > 5
    relevant = opt.slice_for_query([c1, c2, c3, c4, c5], query_a)
    relevant_ids = {id(r) for r in relevant}
    assert id(c1) in relevant_ids, "c1 should be relevant (shares 'a')"
    assert id(c2) in relevant_ids, "c2 should be relevant (shares 'b', merged via c4)"
    assert id(c4) in relevant_ids, "c4 should be relevant (shares 'a' and 'b')"
    assert id(c3) not in relevant_ids, "c3 should NOT be relevant (independent {c,d})"
    assert id(c5) not in relevant_ids, "c5 should NOT be relevant (independent {e})"
    assert len(relevant) == 3, f"Expected 3 relevant, got {len (relevant )}"

    query_e = e < 100
    relevant_e = opt.slice_for_query([c1, c2, c3, c4, c5], query_e)
    assert len(relevant_e) == 1 and id(relevant_e[0]) == id(c5)

    query_c = c > 0
    relevant_c = opt.slice_for_query([c1, c2, c3, c4, c5], query_c)
    assert len(relevant_c) == 1 and id(relevant_c[0]) == id(c3)

    query_const = _z3.BoolVal(True)
    relevant_const = opt.slice_for_query([c1, c2, c3, c4, c5], query_const)
    assert len(relevant_const) == 0

    print(f"  PASS — slicing correct, stats: {opt.get_stats ()}")

    print("\n[TEST 4] Performance simulation (1000 constraints, 500 queries)")
    opt2 = ConstraintIndependenceOptimizer()

    groups_list: list[list[_z3.ArithRef]] = []
    all_constraints: list[_z3.BoolRef] = []
    for g in range(10):
        group_vars = [_z3.Int(f"g{g}_v{i}") for i in range(10)]
        groups_list.append(group_vars)

        for i in range(10):
            v1 = group_vars[i]
            v2 = group_vars[(i + 1) % 10]
            c_new = v1 + v2 > i
            all_constraints.append(c_new)
            opt2.register_constraint(c_new)

    long_path = all_constraints * 10

    import random

    random.seed(42)
    start = time.perf_counter()
    for _ in range(500):
        g_idx = random.randint(0, 9)
        v_idx = random.randint(0, 9)
        query = groups_list[g_idx][v_idx] > random.randint(-100, 100)
        sliced = opt2.slice_for_query(long_path, query)

        assert len(sliced) == 100, f"Group {g_idx}: expected 100 relevant, got {len (sliced )}"
    elapsed = time.perf_counter() - start

    stats2 = opt2.get_stats()
    print(f"  500 queries × 1000 constraints in {elapsed *1000 :.1f} ms")
    print(f"  Reduction ratio: {stats2 ['reduction_ratio']:.1%}")
    print(
        f"  Cache: {stats2 ['full_extractions']} AST walks, "
        f"{stats2 ['cached_extractions']} cache hits"
    )
    assert (
        stats2["reduction_ratio"] > 0.85
    ), f"Expected >85% reduction, got {stats2 ['reduction_ratio']:.1%}"
    print("  PASS — 90% constraint reduction on independent groups")

    print("\n[TEST 5] Edge cases")
    opt3 = ConstraintIndependenceOptimizer()

    assert opt3.slice_for_query([], _z3.Int("x") > 0) == []

    single_c = _z3.Int("x") > 0
    opt3.register_constraint(single_c)
    result = opt3.slice_for_query([single_c], _z3.Int("x") < 10)
    assert len(result) == 1

    result2 = opt3.slice_for_query([single_c], _z3.Int("other") < 10)
    assert len(result2) == 0

    opt4 = ConstraintIndependenceOptimizer()
    cx = _z3.Int("shared") > 0
    cy = _z3.Int("shared") < 100
    cz = _z3.Int("shared") == 50
    for ci in [cx, cy, cz]:
        opt4.register_constraint(ci)
    path = [cx, cy, cz]
    result3 = opt4.slice_for_query(path, _z3.Int("shared") != 0)
    assert result3 is path, "Should return original list when no reduction"

    print("  PASS — empty path, single constraint, no-reduction identity")

    print("\n[TEST 6] Reset clears all state")
    opt.reset()
    assert opt.total_queries == 0
    assert opt.sliced_queries == 0
    print("  PASS")

    print("\n" + "=" * 70)
    print("ALL 6 TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    _run_self_tests()
