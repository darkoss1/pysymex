import pytest

from pysymex.core.memory.unsat_core_registry import BitPackedCoreRegistry

def test_add_core():
    registry = BitPackedCoreRegistry()
    registry.add_core([0, 2])
    assert registry.num_cores == 1
    # The mask should be (1 << 0) | (1 << 2) = 1 | 4 = 5
    assert 5 in registry._cores

def test_is_feasible():
    registry = BitPackedCoreRegistry()
    # Let's say indices 0 and 2 contradict
    registry.add_core([0, 2])
    
    # Path with 0 and 1 -> Feasible
    path1_mask = (1 << 0) | (1 << 1)
    assert registry.is_feasible(path1_mask) is True
    
    # Path with 0, 1, and 2 -> Infeasible (contains core 0, 2)
    path2_mask = (1 << 0) | (1 << 1) | (1 << 2)
    assert registry.is_feasible(path2_mask) is False
    
    # Path with only 2 -> Feasible
    path3_mask = (1 << 2) | (1 << 3)
    assert registry.is_feasible(path3_mask) is True

def test_multiple_cores():
    registry = BitPackedCoreRegistry()
    registry.add_core([0, 1])
    registry.add_core([3, 4])
    
    assert registry.is_feasible((1 << 0) | (1 << 2)) is True
    assert registry.is_feasible((1 << 0) | (1 << 1)) is False
    assert registry.is_feasible((1 << 3) | (1 << 5)) is True
    assert registry.is_feasible((1 << 0) | (1 << 3) | (1 << 4)) is False

def test_clear():
    registry = BitPackedCoreRegistry()
    registry.add_core([0, 1])
    registry.clear()
    assert registry.num_cores == 0
    assert registry.is_feasible((1 << 0) | (1 << 1)) is True
