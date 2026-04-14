import pytest
from pysymex.core.graph.union_find import UnionFind

def test_make_set():
    uf = UnionFind[int]()
    uf.make_set(1)
    assert uf.find(1) == 1

def test_find():
    uf = UnionFind[int]()
    uf.make_set(1)
    uf.make_set(2)
    uf.union(1, 2)
    assert uf.find(1) == uf.find(2)

def test_union():
    uf = UnionFind[int]()
    assert uf.union(1, 2) is True
    assert uf.union(1, 2) is False # Already united
    assert uf.find(1) == uf.find(2)

def test_get_components():
    uf = UnionFind[int]()
    uf.union(1, 2)
    uf.union(3, 4)
    components = uf.get_components()
    assert len(components) == 2
    
    comp1 = next(c for c in components if 1 in c)
    assert set(comp1) == {1, 2}
    
    comp2 = next(c for c in components if 3 in c)
    assert set(comp2) == {3, 4}

def test_clear():
    uf = UnionFind[int]()
    uf.union(1, 2)
    uf.clear()
    assert len(uf.get_components()) == 0
    with pytest.raises(KeyError):
        uf.find(1)
