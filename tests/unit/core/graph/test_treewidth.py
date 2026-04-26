import pysymex.core.graph.treewidth
import z3
from pysymex.core.solver.independence import ConstraintIndependenceOptimizer


def _make_graph() -> pysymex.core.graph.treewidth.ConstraintInteractionGraph:
    return pysymex.core.graph.treewidth.ConstraintInteractionGraph(
        ConstraintIndependenceOptimizer()
    )


class TestBranchInfo:
    """Test suite for pysymex.core.graph.treewidth.BranchInfo."""

    def test_initialization(self) -> None:
        """Scenario: branch info dataclass stores provided metadata."""
        info = pysymex.core.graph.treewidth.BranchInfo(1, frozenset({"x"}), frozenset({"x"}))
        assert info.pc == 1


def test_base_var_name_only_strips_generated_discriminators() -> None:
    assert pysymex.core.graph.treewidth._base_var_name("x_42_int") == "x_42"
    assert pysymex.core.graph.treewidth._base_var_name("x_42_is_bool") == "x_42"
    assert pysymex.core.graph.treewidth._base_var_name("result_is_int") == "result_is_int"


class TestTreeDecomposition:
    """Test suite for pysymex.core.graph.treewidth.TreeDecomposition."""

    def test_get_parent(self) -> None:
        """Scenario: explicit parent map has parent for child bag."""
        td = pysymex.core.graph.treewidth.TreeDecomposition(
            bags={0: frozenset({0}), 1: frozenset({0, 1})},
            tree_edges=[(0, 1)],
            adhesion={(0, 1): frozenset({0})},
            width=1,
            parent_map={0: 1},
        )
        assert td.get_parent(0) == 1


class TestConstraintInteractionGraph:
    """Test suite for pysymex.core.graph.treewidth.ConstraintInteractionGraph."""

    def test_reset(self) -> None:
        """Scenario: reset after adding branch; expected branch map cleared."""
        graph = _make_graph()
        x = z3.Int("x_int")
        graph.add_branch(10, x > 0)
        graph.reset()
        assert graph.num_branches == 0

    def test_num_branches(self) -> None:
        """Scenario: add one branch; expected branch count to be one."""
        graph = _make_graph()
        x = z3.Int("x_int")
        graph.add_branch(1, x > 0)
        assert graph.num_branches == 1

    def test_estimated_treewidth(self) -> None:
        """Scenario: independent branches; expected treewidth estimate zero."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        graph.add_branch(2, z3.Int("y_int") > 0)
        assert graph.estimated_treewidth == 0

    def test_branch_info(self) -> None:
        """Scenario: branch registration stores metadata keyed by PC."""
        graph = _make_graph()
        graph.add_branch(4, z3.Int("x_int") > 0)
        assert 4 in graph.branch_info

    def test_adjacency(self) -> None:
        """Scenario: shared variable creates edge between branches."""
        graph = _make_graph()
        x = z3.Int("x_int")
        graph.add_branch(1, x > 0)
        graph.add_branch(2, x < 3)
        assert graph.adjacency[1] == {2}

    def test_add_branch(self) -> None:
        """Scenario: add branch returns info containing same PC."""
        graph = _make_graph()
        info = graph.add_branch(7, z3.Int("x_int") == 1)
        assert info.pc == 7

    def test_is_stabilized(self) -> None:
        """Scenario: insufficient branches; expected not stabilized."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        assert graph.is_stabilized() is False

    def test_is_stabilized_with_relaxed_defaults(self) -> None:
        """Scenario: three stable branches should satisfy the new defaults."""
        graph = _make_graph()
        x = z3.Int("x_int")
        graph.add_branch(1, x > 0)
        graph.add_branch(2, x > 1)
        graph.add_branch(3, x > 2)
        graph._branches_since_last_tw_change = 4
        assert graph.is_stabilized() is True

    def test_compute_tree_decomposition(self) -> None:
        """Scenario: decomposition on small graph; expected non-negative width."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        td = graph.compute_tree_decomposition()
        assert td.width >= 0

    def test_extract_skeleton(self) -> None:
        """Scenario: independent single-vertex graph; expected empty skeleton."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        assert graph.extract_skeleton() == frozenset()

    def test_get_independent_groups(self) -> None:
        """Scenario: two disconnected branches; expected two independent groups."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        graph.add_branch(2, z3.Int("y_int") > 0)
        assert len(graph.get_independent_groups()) == 2

    def test_get_stats(self) -> None:
        """Scenario: stats call after branch insertion; expected branch count in stats."""
        graph = _make_graph()
        graph.add_branch(1, z3.Int("x_int") > 0)
        assert graph.get_stats()["branches"] == 1
