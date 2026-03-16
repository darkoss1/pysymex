"""Pytest tests for the Constraint Independence Optimizer.

Migrated from the inline self-tests in core/constraint_independence.py (Issue 16).
"""

from __future__ import annotations

import random
import time

import pytest
import z3

from pysymex.core.constraint_independence import (
    ConstraintIndependenceOptimizer,
    UnionFind,
)


class TestUnionFind:
    """TEST 1: Union-Find basic operations."""

    def test_find_creates_singleton(self):
        uf = UnionFind()
        assert uf.find("a") == "a"
        assert uf.find("b") == "b"

    def test_initially_disconnected(self):
        uf = UnionFind()
        uf.find("a")
        uf.find("b")
        assert not uf.connected("a", "b")

    def test_union_connects(self):
        uf = UnionFind()
        uf.union("a", "b")
        assert uf.connected("a", "b")
        assert not uf.connected("a", "c")

    def test_transitive_connectivity(self):
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        assert uf.connected("a", "c")

    def test_separate_groups(self):
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("d", "e")
        assert not uf.connected("a", "d")

    def test_full_merge(self):
        uf = UnionFind()
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("d", "e")
        uf.union("c", "d")
        assert uf.connected("a", "e")
        groups = uf.groups()
        assert len(groups) == 1, f"Expected 1 group, got {len(groups)}"


class TestVariableExtraction:
    """TEST 2: Z3 variable extraction + caching."""

    def setup_method(self):
        self.opt = ConstraintIndependenceOptimizer()
        self.x = z3.Int("x")
        self.y = z3.Int("y")
        self.z = z3.Int("z")

    def test_simple_extraction(self):
        expr = self.x + self.y > 5
        assert self.opt.get_variables(expr) == frozenset({"x", "y"})

    def test_extraction_cache_hit(self):
        expr = self.x + self.y > 5
        vars1 = self.opt.get_variables(expr)
        vars2 = self.opt.get_variables(expr)
        assert vars1 == vars2

    def test_single_var(self):
        assert self.opt.get_variables(self.z < 10) == frozenset({"z"})

    def test_nested_and_or(self):
        expr = z3.And(self.x > 0, z3.Or(self.y < 10, self.z == 42))
        assert self.opt.get_variables(expr) == frozenset({"x", "y", "z"})

    def test_constant_true(self):
        assert self.opt.get_variables(z3.BoolVal(True)) == frozenset()

    def test_constant_comparison(self):
        assert self.opt.get_variables(z3.IntVal(42) > z3.IntVal(10)) == frozenset()

    def test_stats_populated(self):
        self.opt.get_variables(self.x + self.y > 5)
        self.opt.get_variables(self.x + self.y > 5)
        self.opt.get_variables(self.z < 10)
        self.opt.get_variables(z3.BoolVal(True))
        self.opt.get_variables(z3.IntVal(42) > z3.IntVal(10))
        stats = self.opt.get_stats()
        assert int(stats["full_extractions"]) >= 4
        assert int(stats["cached_extractions"]) >= 1


class TestConstraintSlicing:
    """TEST 3: Constraint slicing — independent clusters."""

    def setup_method(self):
        self.opt = ConstraintIndependenceOptimizer()
        a = z3.Int("a")
        b = z3.Int("b")
        c = z3.Int("c")
        d = z3.Int("d")
        e = z3.Int("e")

        self.c1 = a > 0
        self.c2 = b < 10
        self.c3 = c + d > 5
        self.c4 = a + b < 20
        self.c5 = e == 42

        for ci in [self.c1, self.c2, self.c3, self.c4, self.c5]:
            self.opt.register_constraint(ci)

        self.a, self.e, self.c_var = a, e, c

    def test_query_shared_cluster(self):
        relevant = self.opt.slice_for_query(
            [self.c1, self.c2, self.c3, self.c4, self.c5], self.a > 5
        )
        relevant_ids = {id(r) for r in relevant}
        assert id(self.c1) in relevant_ids
        assert id(self.c2) in relevant_ids
        assert id(self.c4) in relevant_ids
        assert id(self.c3) not in relevant_ids
        assert id(self.c5) not in relevant_ids
        assert len(relevant) == 3

    def test_query_isolated_e(self):
        relevant = self.opt.slice_for_query(
            [self.c1, self.c2, self.c3, self.c4, self.c5], self.e < 100
        )
        assert len(relevant) == 1 and id(relevant[0]) == id(self.c5)

    def test_query_isolated_cd(self):
        relevant = self.opt.slice_for_query(
            [self.c1, self.c2, self.c3, self.c4, self.c5], self.c_var > 0
        )
        assert len(relevant) == 1 and id(relevant[0]) == id(self.c3)

    def test_query_constant(self):
        relevant = self.opt.slice_for_query(
            [self.c1, self.c2, self.c3, self.c4, self.c5], z3.BoolVal(True)
        )
        assert len(relevant) == 0


class TestPerformance:
    """TEST 4: Performance simulation (1000 constraints, 500 queries)."""

    def test_large_workload_reduction(self):
        opt = ConstraintIndependenceOptimizer()
        groups_list: list[list[z3.ArithRef]] = []
        all_constraints: list[z3.BoolRef] = []

        for g in range(10):
            group_vars = [z3.Int(f"g{g}_v{i}") for i in range(10)]
            groups_list.append(group_vars)
            for i in range(10):
                v1 = group_vars[i]
                v2 = group_vars[(i + 1) % 10]
                c = v1 + v2 > i
                all_constraints.append(c)
                opt.register_constraint(c)

        long_path = all_constraints * 10

        rng = random.Random(42)
        for _ in range(500):
            g_idx = rng.randint(0, 9)
            v_idx = rng.randint(0, 9)
            query = groups_list[g_idx][v_idx] > rng.randint(-100, 100)
            sliced = opt.slice_for_query(long_path, query)
            assert len(sliced) == 100, (
                f"Group {g_idx}: expected 100 relevant, got {len(sliced)}"
            )

        stats = opt.get_stats()
        assert float(stats["reduction_ratio"]) > 0.85  # type: ignore[arg-type]


class TestEdgeCases:
    """TEST 5: Edge cases."""

    def test_empty_path(self):
        opt = ConstraintIndependenceOptimizer()
        assert opt.slice_for_query([], z3.Int("x") > 0) == []

    def test_single_constraint(self):
        opt = ConstraintIndependenceOptimizer()
        c = z3.Int("x") > 0
        opt.register_constraint(c)
        assert len(opt.slice_for_query([c], z3.Int("x") < 10)) == 1

    def test_unrelated_query(self):
        opt = ConstraintIndependenceOptimizer()
        c = z3.Int("x") > 0
        opt.register_constraint(c)
        assert len(opt.slice_for_query([c], z3.Int("other") < 10)) == 0

    def test_no_reduction_returns_original(self):
        opt = ConstraintIndependenceOptimizer()
        cx = z3.Int("shared") > 0
        cy = z3.Int("shared") < 100
        cz = z3.Int("shared") == 50
        for ci in [cx, cy, cz]:
            opt.register_constraint(ci)
        path = [cx, cy, cz]
        result = opt.slice_for_query(path, z3.Int("shared") != 0)
        assert result is path


class TestReset:
    """TEST 6: Reset clears all state."""

    def test_reset(self):
        opt = ConstraintIndependenceOptimizer()
        x = z3.Int("x")
        c = x > 0
        opt.register_constraint(c)
        opt.slice_for_query([c], x < 10)

        opt.reset()
        assert opt.total_queries == 0
        assert opt.sliced_queries == 0
