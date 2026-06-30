import gc
import weakref
from typing import cast

import z3

from pysymex._internal.core.solver.independence.optimizer import IndependenceOptimizer
from pysymex._internal.core.solver.independence.union.find import ConstraintUnionFind


class _InspectableOptimizer(IndependenceOptimizer):
    def first_slice_cache_key(self) -> int:
        return next(iter(self._slice_cache))

    def first_slice_cache_entry(
        self,
    ) -> tuple[
        tuple[weakref.ReferenceType[z3.BoolRef], ...],
        weakref.ReferenceType[z3.BoolRef],
        tuple[int, ...],
    ]:
        return self._slice_cache[self.first_slice_cache_key()][0]

    def clear_expression_caches(self) -> None:
        self._var_cache.clear()

    def lookup_slice_cache(
        self,
        cache_key: int,
        path_constraints: list[z3.BoolRef],
        query: z3.BoolRef,
    ) -> list[z3.BoolRef] | None:
        return self._lookup_slice_cache(cache_key, path_constraints, query)


class TestConstraintUnionFind:
    """Test suite for the solver constraint-union-find adapter."""

    def test_find(self) -> None:
        """Scenario: first find on unseen element; expected element as its own root."""
        uf = ConstraintUnionFind()
        assert uf.find("a") == "a"

    def test_union(self) -> None:
        """Scenario: union two singleton sets; expected shared connectivity."""
        uf = ConstraintUnionFind()
        root = uf.union("a", "b")
        assert uf.connected("a", "b") is True
        assert root == uf.find("a")

    def test_connected(self) -> None:
        """Scenario: elements not unioned; expected not connected."""
        uf = ConstraintUnionFind()
        assert uf.connected("x", "y") is False

    def test_groups(self) -> None:
        """Scenario: one merged pair and one singleton; expected two groups."""
        uf = ConstraintUnionFind()
        _ = uf.union("a", "b")
        _ = uf.find("c")
        assert {frozenset(group) for group in uf.groups().values()} == {
            frozenset({"a", "b"}),
            frozenset({"c"}),
        }


class TestConstraintIndependenceOptimizer:
    """Test suite for pysymex._internal.core.solver.independence.optimizer.ConstraintIndependenceOptimizer."""

    def test_reset(self) -> None:
        """Scenario: reset after registration; expected stats counters cleared."""
        opt = IndependenceOptimizer()
        _ = opt.register_constraint(z3.Int("x") > 0)
        opt.reset()
        assert opt.get_stats()["total_queries"] == 0
        assert opt.constraint_index == 0
        assert opt.var_to_constraint_indices == {}

    def test_register_constraint(self) -> None:
        """Scenario: register x>0 constraint; expected variable set contains x."""
        opt = IndependenceOptimizer()
        vars_set = opt.register_constraint(z3.Int("x") > 0)
        assert "x" in vars_set

    def test_get_variables(self) -> None:
        """Scenario: get variables on x+y expression; expected both names present."""
        opt = IndependenceOptimizer()
        x = z3.Int("x")
        y = z3.Int("y")
        vars_set = opt.get_variables(x + y > 0)
        assert vars_set == frozenset({"x", "y"})

    def test_slice_for_query(self) -> None:
        """Scenario: query depends on one cluster; expected unrelated constraint sliced out."""
        opt = IndependenceOptimizer()
        x = z3.Int("x")
        y = z3.Int("y")
        c1 = x > 0
        c2 = y > 0
        _ = opt.register_constraint(c1)
        _ = opt.register_constraint(c2)
        sliced = opt.slice_for_query([c1, c2], x < 10)
        assert sliced == [c1]

    def test_slice_for_query_is_transitively_dependency_closed(self) -> None:
        """Scenario: x-y-z chain; expected query on z keeps all transitive constraints."""
        opt = IndependenceOptimizer()
        x = z3.Int("slice_tc_x")
        y = z3.Int("slice_tc_y")
        z = z3.Int("slice_tc_z")
        unrelated = z3.Int("slice_tc_unrelated")
        c1 = x == y
        c2 = y == z
        c3 = unrelated > 0
        for constraint in (c1, c2, c3):
            _ = opt.register_constraint(constraint)

        sliced = opt.slice_for_query([c1, c2, c3], z > 10)

        assert sliced == [c1, c2]

    def test_slice_for_query_keeps_uninterpreted_function_dependencies(self) -> None:
        """Scenario: zero-variable UF application; expected UF token keeps constraint."""
        opt = IndependenceOptimizer()
        f = z3.Function("slice_uf_f", z3.IntSort(), z3.IntSort())
        c1 = f(0) == 1
        c2 = z3.Int("slice_uf_unrelated") > 0
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        sliced = opt.slice_for_query([c1, c2], f(0) != 1)

        assert sliced == [c1]
        assert any(token.startswith("uf:slice_uf_f") for token in opt.get_variables(c1))

    def test_get_variables_handles_quantifiers_without_application_decl_crash(self) -> None:
        """Scenario: quantified formula; expected dependency extraction does not crash."""
        opt = IndependenceOptimizer()
        x = z3.Int("slice_quantifier_x")
        y = z3.Int("slice_quantifier_y")
        quantified = z3.ForAll([x], x == x)

        variables = opt.get_variables(quantified)
        sliced = opt.slice_for_query([quantified], y > 0)

        assert isinstance(variables, frozenset)
        assert sliced == [quantified]

    def test_slice_for_query_tracks_array_ssa_heap_and_memory_epoch_tokens(self) -> None:
        """Scenario: array, SSA, heap, and memory-epoch symbols; expected closed slice."""
        opt = IndependenceOptimizer()
        arr = z3.Array("slice_arr", z3.IntSort(), z3.IntSort())
        ssa_index = z3.Int("slice_idx_ssa_3")
        heap_obj = z3.Int("slice_heap_obj_9")
        memory_epoch = z3.Int("slice_memory_epoch_4")
        unrelated = z3.Int("slice_memory_unrelated")
        c1 = z3.Select(arr, ssa_index) == heap_obj
        c2 = heap_obj == memory_epoch
        c3 = unrelated == 0
        for constraint in (c1, c2, c3):
            _ = opt.register_constraint(constraint)

        sliced = opt.slice_for_query([c1, c2, c3], z3.Select(arr, ssa_index) != memory_epoch)

        assert sliced == [c1, c2]

    def test_slice_for_query_reuses_cached_dependency_closure(self) -> None:
        """Scenario: repeated exact prefix/query; expected slice closure cache hit."""
        opt = IndependenceOptimizer()
        x = z3.Int("slice_cache_x")
        y = z3.Int("slice_cache_y")
        c1 = x > 0
        c2 = y > 0
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        first = opt.slice_for_query([c1, c2], x < 10)
        second = opt.slice_for_query([c1, c2], x < 10)
        stats = opt.get_stats()

        assert first == [c1]
        assert second == [c1]
        assert stats["slice_cache_hits"] == 1
        assert stats["slice_cache_misses"] == 1

    def test_slice_cache_weakly_references_z3_expressions(self) -> None:
        """Scenario: cached slice expressions die; expected stale cache entry is pruned."""
        opt = _InspectableOptimizer()
        x = z3.Int("slice_weak_x")
        y = z3.Int("slice_weak_y")
        c1 = x > 0
        c2 = y > 0
        query = x < 10
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        slice_result = opt.slice_for_query([c1, c2], query)
        cache_key = opt.first_slice_cache_key()
        entry = opt.first_slice_cache_entry()
        c1_ref = weakref.ref(c1)

        assert isinstance(entry[0][0], weakref.ReferenceType)
        assert isinstance(entry[1], weakref.ReferenceType)

        opt.clear_expression_caches()
        del c1, c2, query, constraint, slice_result
        gc.collect()

        assert c1_ref() is None
        assert opt.lookup_slice_cache(cache_key, [], z3.BoolVal(True)) is None
        assert opt.get_stats()["slice_cache_size"] == 0

    def test_slice_cache_validates_similar_ssa_memory_queries(self) -> None:
        """Scenario: similar array queries with different epochs; expected validated reuse."""
        opt = IndependenceOptimizer()
        arr_epoch_1 = z3.Array("cache_arr_epoch_1", z3.IntSort(), z3.IntSort())
        arr_epoch_2 = z3.Array("cache_arr_epoch_2", z3.IntSort(), z3.IntSort())
        idx_ssa_1 = z3.Int("cache_idx_ssa_1")
        idx_ssa_2 = z3.Int("cache_idx_ssa_2")
        heap_epoch_1 = z3.Int("cache_heap_obj_1_memory_epoch_1")
        heap_epoch_2 = z3.Int("cache_heap_obj_1_memory_epoch_2")
        c1 = z3.Select(arr_epoch_1, idx_ssa_1) == heap_epoch_1
        c2 = z3.Select(arr_epoch_2, idx_ssa_2) == heap_epoch_2
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        first = opt.slice_for_query([c1, c2], z3.Select(arr_epoch_1, idx_ssa_1) != heap_epoch_1)
        second = opt.slice_for_query([c1, c2], z3.Select(arr_epoch_2, idx_ssa_2) != heap_epoch_2)
        third = opt.slice_for_query([c1, c2], z3.Select(arr_epoch_1, idx_ssa_1) != heap_epoch_1)
        stats = opt.get_stats()

        assert first == [c1]
        assert second == [c2]
        assert third == [c1]
        assert stats["slice_cache_hits"] == 1
        assert stats["slice_cache_misses"] == 2

    def test_adaptive_slicing_disablement_falls_back_to_full_prefix(self) -> None:
        """Scenario: dense unhelpful slices; expected safe full-prefix fallback."""
        opt = IndependenceOptimizer(
            adaptive_disable_min_queries=2,
            adaptive_disable_min_reduction=0.5,
        )
        x = z3.Int("slice_disable_x")
        y = z3.Int("slice_disable_y")
        c1 = x > 0
        c2 = x < 10
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        assert opt.slice_for_query([c1, c2], x != 5) == [c1, c2]
        assert opt.slice_for_query([c1, c2], x != 6) == [c1, c2]

        disabled_result = opt.slice_for_query([c1, c2], y > 0)
        stats = opt.get_stats()

        assert disabled_result == [c1, c2]
        assert stats["slicing_disabled"] is True
        assert stats["slicing_disabled_count"] == 1

    def test_adaptive_slice_cache_disable_keeps_slicing_enabled(self) -> None:
        """Scenario: no slice-cache reuse; expected cache disabled but slicing retained."""
        opt = IndependenceOptimizer(
            slice_cache_disable_min_attempts=2,
            slice_cache_disable_max_hit_rate=0.0,
        )
        x = z3.Int("slice_cache_disable_x")
        y = z3.Int("slice_cache_disable_y")
        c1 = x > 0
        c2 = y > 0
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        assert opt.slice_for_query([c1, c2], x < 10) == [c1]
        assert opt.slice_for_query([c1, c2], y < 10) == [c2]
        assert opt.slice_for_query([c1, c2], x < 11) == [c1]
        stats = opt.get_stats()

        assert stats["slice_cache_enabled"] is False
        assert stats["slice_cache_disabled_count"] == 1
        assert stats["slice_cache_size"] == 0
        assert stats["slicing_disabled"] is False

    def test_get_stats(self) -> None:
        """Scenario: stats after one slice query; expected total_queries increments to one."""
        opt = IndependenceOptimizer()
        x = z3.Int("x")
        c = x > 0
        _ = opt.register_constraint(c)
        _ = opt.slice_for_query([c], x < 2)
        assert opt.get_stats()["total_queries"] == 1

    def test_register_constraint_tracks_temporal_indices(self) -> None:
        """Scenario: registration should advance the temporal index and record variable history."""
        opt = IndependenceOptimizer()
        x = z3.Int("x")
        y = z3.Int("y")
        _ = opt.register_constraint(x + y > 0)
        assert opt.constraint_index == 1
        assert opt.var_to_constraint_indices["x"] == [0]
        assert opt.var_to_constraint_indices["y"] == [0]

    def test_sync_registered_path_reuses_prefix_and_resets_on_branch_switch(self) -> None:
        """Scenario: registered prefix sync; expected exact path dependency ownership."""
        opt = IndependenceOptimizer()
        x = z3.Int("sync_path_x")
        y = z3.Int("sync_path_y")
        c1 = x > 0
        c2 = y > 0

        opt.sync_registered_path([c1])
        first_full = opt.get_stats()["full_extractions"]
        opt.sync_registered_path([c1])
        same_full = opt.get_stats()["full_extractions"]
        opt.sync_registered_path([c1, c2])
        extended_full = opt.get_stats()["full_extractions"]
        opt.sync_registered_path([c2])

        assert same_full == first_full
        assert cast(int, extended_full) == cast(int, first_full) + 1
        assert opt.constraint_index == 1
        assert opt.var_to_constraint_indices == {"sync_path_y": [0]}

    def test_extract_variables_reuses_ast_id_cache(self) -> None:
        """Scenario: repeated extraction on the same AST should hit the variable cache."""
        opt = IndependenceOptimizer()
        x = z3.Int("cache_reuse_x")
        expr = x > 0
        first = opt.get_variables(expr)
        cached_before = opt.get_stats()["cached_extractions"]
        second = opt.get_variables(expr)
        cached_after = opt.get_stats()["cached_extractions"]

        assert first == frozenset({"cache_reuse_x"})
        assert second == first
        assert cast(int, cached_after) == cast(int, cached_before) + 1

    def test_extract_variables_keeps_distinct_asts_separate(self) -> None:
        """Scenario: different AST nodes must not share variable-extraction cache entries."""
        opt = IndependenceOptimizer()
        x = z3.Int("cache_distinct_x")
        y = z3.Int("cache_distinct_y")
        assert opt.get_variables(x > 0) == frozenset({"cache_distinct_x"})
        assert opt.get_variables(y > 0) == frozenset({"cache_distinct_y"})
