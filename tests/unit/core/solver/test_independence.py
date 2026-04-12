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
        assert opt._constraint_index == 0
        assert opt._var_to_constraint_indices == {}

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
        assert opt._constraint_index == 1
        assert opt._var_to_constraint_indices["x"] == [0]
        assert opt._var_to_constraint_indices["y"] == [0]

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
