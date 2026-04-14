import pytest
from pysymex.core.graph.cig import ConstraintInteractionGraph

def test_add_branch():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(["x", "y"]))
    assert cig.num_vertices == 1
    assert cig.num_edges == 0

def test_get_degree():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(["x"]))
    cig.add_branch(104, frozenset(["x", "y"]))
    assert cig.get_degree(100) == 1
    assert cig.get_degree(104) == 1

def test_get_neighbors():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(["x"]))
    cig.add_branch(104, frozenset(["x", "y"]))
    cig.add_branch(108, frozenset(["y"]))
    
    assert cig.get_neighbors(104) == {100, 108}
    assert cig.get_neighbors(100) == {104}
    assert cig.get_neighbors(108) == {104}

def test_no_shared_vars():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(["x"]))
    cig.add_branch(104, frozenset(["y"]))
    assert cig.num_edges == 0

def test_clear():
    cig = ConstraintInteractionGraph()
    cig.add_branch(100, frozenset(["x"]))
    cig.clear()
    assert cig.num_vertices == 0
    assert cig.num_edges == 0
    assert cig.get_degree(100) == 0
