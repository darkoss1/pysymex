"""Tests for pysymex.core.memory.unsat_core_registry."""

from typing import Set

from pysymex.core.memory.unsat_core_registry import SparseCoreRegistry


class TestSparseCoreRegistry:
    def test_add_core_ignores_empty_list(self) -> None:
        registry = SparseCoreRegistry()
        registry.add_core([])
        assert registry.num_cores == 0

    def test_add_core_stores_sparse_frozenset(self) -> None:
        registry = SparseCoreRegistry()
        registry.add_core([1, 2, 3])
        assert registry.num_cores == 1

    def test_is_feasible_returns_true_for_empty_registry(self) -> None:
        registry = SparseCoreRegistry()
        path: Set[int] = {1, 2}
        assert registry.is_feasible(path) is True

    def test_is_feasible_returns_true_for_partial_match(self) -> None:
        registry = SparseCoreRegistry()
        registry.add_core([1, 2, 3])
        path: Set[int] = {1, 2}
        assert registry.is_feasible(path) is True

    def test_is_feasible_returns_false_for_full_match(self) -> None:
        registry = SparseCoreRegistry()
        registry.add_core([1, 2])
        path: Set[int] = {1, 2, 3}
        assert registry.is_feasible(path) is False

    def test_num_cores_tracks_count(self) -> None:
        registry = SparseCoreRegistry()
        assert registry.num_cores == 0
        registry.add_core([1])
        assert registry.num_cores == 1

    def test_clear_removes_all_state(self) -> None:
        registry = SparseCoreRegistry()
        registry.add_core([1, 2])
        registry.clear()
        assert registry.num_cores == 0
        path: Set[int] = {1, 2}
        assert registry.is_feasible(path) is True
