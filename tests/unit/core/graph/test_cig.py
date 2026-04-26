"""Tests for pysymex.core.graph.cig."""

from typing import FrozenSet, Hashable

from pysymex.core.graph.cig import ConstraintInteractionGraph


class TestConstraintInteractionGraph:
    def test_add_branch_creates_vertex(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        assert cig.num_vertices == 1
        assert cig.get_degree(10) == 0

    def test_add_branch_ignores_duplicate_pc(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(10, vars_set)
        assert cig.num_vertices == 1

    def test_add_branch_creates_edges_on_shared_vars(self) -> None:
        cig = ConstraintInteractionGraph()
        vars1: FrozenSet[Hashable] = frozenset(["x", "y"])
        vars2: FrozenSet[Hashable] = frozenset(["y", "z"])
        cig.add_branch(10, vars1)
        cig.add_branch(20, vars2)
        assert cig.num_edges == 1
        assert cig.get_degree(10) == 1
        assert 20 in cig.get_neighbors(10)

    def test_add_branch_no_edges_on_disjoint_vars(self) -> None:
        cig = ConstraintInteractionGraph()
        vars1: FrozenSet[Hashable] = frozenset(["x"])
        vars2: FrozenSet[Hashable] = frozenset(["y"])
        cig.add_branch(10, vars1)
        cig.add_branch(20, vars2)
        assert cig.num_edges == 0
        assert cig.get_degree(10) == 0
        assert 20 not in cig.get_neighbors(10)

    def test_get_degree_returns_correct_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        cig.add_branch(30, vars_set)
        assert cig.get_degree(10) == 2

    def test_get_neighbors_returns_correct_set(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        assert cig.get_neighbors(10) == {20}
        assert cig.get_neighbors(99) == set()

    def test_num_vertices_tracks_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        assert cig.num_vertices == 0
        cig.add_branch(10, vars_set)
        assert cig.num_vertices == 1

    def test_num_edges_tracks_count(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        assert cig.num_edges == 0
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        assert cig.num_edges == 1

    def test_clear_removes_all_state(self) -> None:
        cig = ConstraintInteractionGraph()
        vars_set: FrozenSet[Hashable] = frozenset(["x"])
        cig.add_branch(10, vars_set)
        cig.add_branch(20, vars_set)
        cig.clear()
        assert cig.num_vertices == 0
        assert cig.num_edges == 0
        assert cig.get_neighbors(10) == set()
