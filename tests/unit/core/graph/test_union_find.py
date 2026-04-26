"""Tests for pysymex.core.graph.union_find."""

import pytest

from pysymex.core.graph.union_find import UnionFind


class TestUnionFind:
    def test_make_set_creates_isolated_set(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.make_set(1)
        assert uf.find(1) == 1

    def test_find_returns_self_for_isolated_set(self) -> None:
        uf: UnionFind[str] = UnionFind()
        uf.make_set("a")
        assert uf.find("a") == "a"

    def test_find_performs_path_compression(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.union(1, 2)
        uf.union(2, 3)
        root = uf.find(1)
        assert uf.find(1) == root

    def test_union_returns_true_on_new_union(self) -> None:
        uf: UnionFind[int] = UnionFind()
        result = uf.union(1, 2)
        assert result is True

    def test_union_returns_false_on_existing_union(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.union(1, 2)
        result = uf.union(1, 2)
        assert result is False

    def test_union_uses_union_by_rank(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.union(1, 2)
        uf.union(3, 4)
        uf.union(1, 3)
        assert uf.find(1) == uf.find(4)

    def test_get_components_returns_disjoint_sets(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.union(1, 2)
        uf.union(3, 4)
        components = uf.get_components()
        assert len(components) == 2
        comp1 = set(components[0])
        comp2 = set(components[1])
        assert (comp1 == {1, 2} and comp2 == {3, 4}) or (comp1 == {3, 4} and comp2 == {1, 2})

    def test_clear_removes_all_state(self) -> None:
        uf: UnionFind[int] = UnionFind()
        uf.union(1, 2)
        uf.clear()
        with pytest.raises(KeyError):
            uf.find(1)
