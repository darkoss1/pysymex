"""Tests for pysymex._internal.core.graph.cig."""

import importlib
from collections.abc import Hashable

from pysymex._internal.core.graph.cig import ConstraintInteractionGraph


class TestConstraintInteractionGraph:
    def test_graph_package_is_documentation_only(self) -> None:
        graph_package = importlib.import_module("pysymex._internal.core.graph")

        assert "ConstraintInteractionGraph" not in vars(graph_package)

    def test_add_branch_creates_vertex(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        assert cig.num_branches == 1
        assert cig.get_degree(10) == 0

    def test_add_branch_ignores_duplicate_pc(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(10, vars_set)
        assert cig.num_branches == 1

    def test_add_branch_creates_edges_on_shared_vars(self) -> None:
        cig = ConstraintInteractionGraph()
        vars1: frozenset[Hashable] = frozenset(["x", "y"])
        vars2: frozenset[Hashable] = frozenset(["y", "z"])
        cig.add_branch(10, vars1)
        cig.add_branch(20, vars2)
        assert cig.num_edges == 1
        assert cig.get_degree(10) == 1
        assert 20 in cig.adjacency[10]

    def test_add_branch_no_edges_on_disjoint_vars(self) -> None:
        cig = ConstraintInteractionGraph()
        vars1: frozenset[Hashable] = frozenset(["x"])
        vars2: frozenset[Hashable] = frozenset(["y"])
        cig.add_branch(10, vars1)
        cig.add_branch(20, vars2)
        assert cig.num_edges == 0
        assert cig.get_degree(10) == 0
        assert 20 not in cig.adjacency.get(10, set())

    def test_get_degree_returns_correct_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        cig.add_branch(30, vars_set)
        assert cig.get_degree(10) == 2

    def test_adjacency_tracks_neighbors(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        assert cig.adjacency[10] == {20}
        assert cig.adjacency.get(99, set()) == set()

    def test_num_branches_tracks_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        assert cig.num_branches == 0
        cig.add_branch(10, vars_set)
        assert cig.num_branches == 1

    def test_num_edges_tracks_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        assert cig.num_edges == 0
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        assert cig.num_edges == 1

    def test_reset_removes_all_state(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: frozenset[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        cig.reset()
        assert cig.num_branches == 0
        assert cig.num_edges == 0
        assert cig.adjacency.get(10, set()) == set()
