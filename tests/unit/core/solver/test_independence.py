import pysymex.core.solver.independence
import z3
from unittest.mock import patch


class TestUnionFind:
    """Test suite for pysymex.core.solver.independence.UnionFind."""

    def test_find(self) -> None:
        """Scenario: first find on unseen element; expected element as its own root."""
        uf = pysymex.core.solver.independence.UnionFind()
        assert uf.find("a") == "a"

    def test_union(self) -> None:
        """Scenario: union two singleton sets; expected shared connectivity."""
        uf = pysymex.core.solver.independence.UnionFind()
        _ = uf.union("a", "b")
        assert uf.connected("a", "b") is True

    def test_connected(self) -> None:
        """Scenario: elements not unioned; expected not connected."""
        uf = pysymex.core.solver.independence.UnionFind()
        assert uf.connected("x", "y") is False

    def test_groups(self) -> None:
        """Scenario: one merged pair and one singleton; expected two groups."""
        uf = pysymex.core.solver.independence.UnionFind()
        _ = uf.union("a", "b")
        _ = uf.find("c")
        assert len(uf.groups()) == 2


class TestConstraintIndependenceOptimizer:
    """Test suite for pysymex.core.solver.independence.ConstraintIndependenceOptimizer."""

    def test_reset(self) -> None:
        """Scenario: reset after registration; expected stats counters cleared."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        _ = opt.register_constraint(z3.Int("x") > 0)
        opt.reset()
        assert opt.get_stats()["total_queries"] == 0
        assert opt._constraint_index == 0  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        assert opt._var_to_constraint_indices == {}  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    def test_register_constraint(self) -> None:
        """Scenario: register x>0 constraint; expected variable set contains x."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        vars_set = opt.register_constraint(z3.Int("x") > 0)
        assert "x" in vars_set

    def test_get_variables(self) -> None:
        """Scenario: get variables on x+y expression; expected both names present."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        x = z3.Int("x")
        y = z3.Int("y")
        vars_set = opt.get_variables(x + y > 0)
        assert vars_set == frozenset({"x", "y"})

    def test_slice_for_query(self) -> None:
        """Scenario: query depends on one cluster; expected unrelated constraint sliced out."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
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
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
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
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
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
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        x = z3.Int("slice_quantifier_x")
        y = z3.Int("slice_quantifier_y")
        quantified = z3.ForAll([x], x == x)

        variables = opt.get_variables(quantified)
        sliced = opt.slice_for_query([quantified], y > 0)

        assert isinstance(variables, frozenset)
        assert sliced == [quantified]

    def test_slice_for_query_tracks_array_ssa_heap_and_memory_epoch_tokens(self) -> None:
        """Scenario: array, SSA, heap, and memory-epoch symbols; expected closed slice."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
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
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        x = z3.Int("slice_cache_x")
        y = z3.Int("slice_cache_y")
        c1 = x > 0
        c2 = y > 0
        for constraint in (c1, c2):
            _ = opt.register_constraint(constraint)

        first = opt.slice_for_query([c1, c2], x < 10)
        second = opt.slice_for_query([c1, c2], x < 10)
        stats = opt.get_stats()
        theory_full = stats["theory_signature_full"]
        theory_cached = stats["theory_signature_cached"]

        assert first == [c1]
        assert second == [c1]
        assert stats["slice_cache_hits"] == 1
        assert stats["slice_cache_misses"] == 1
        assert isinstance(theory_full, int)
        assert isinstance(theory_cached, int)
        assert theory_full >= 3
        assert theory_cached >= 1

    def test_slice_cache_distinguishes_ssa_memory_and_theory_signatures(self) -> None:
        """Scenario: similar array queries with different epochs; expected distinct cache keys."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
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
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer(
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

    def test_get_stats(self) -> None:
        """Scenario: stats after one slice query; expected total_queries increments to one."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        x = z3.Int("x")
        c = x > 0
        _ = opt.register_constraint(c)
        _ = opt.slice_for_query([c], x < 2)
        assert opt.get_stats()["total_queries"] == 1

    def test_register_constraint_tracks_temporal_indices(self) -> None:
        """Scenario: registration should advance the temporal index and record variable history."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer(temporal_window=2)
        x = z3.Int("x")
        y = z3.Int("y")
        _ = opt.register_constraint(x + y > 0)
        assert opt._constraint_index == 1  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        assert opt._var_to_constraint_indices["x"] == [0]  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state
        assert opt._var_to_constraint_indices["y"] == [0]  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    def test_extract_variables_handles_hash_collisions_safely(self) -> None:
        """Scenario: colliding cache keys should still keep distinct variable sets."""
        opt = pysymex.core.solver.independence.ConstraintIndependenceOptimizer()
        x = z3.Int("x")
        y = z3.Int("y")
        with patch.object(
            pysymex.core.solver.independence.ConstraintIndependenceOptimizer,
            "_cache_key",
            return_value=1,
        ):
            assert opt.get_variables(x > 0) == frozenset({"x"})
            assert opt.get_variables(y > 0) == frozenset({"y"})
