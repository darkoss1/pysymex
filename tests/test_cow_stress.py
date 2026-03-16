import pytest
from pysymex.core.copy_on_write import CowDict
from pysymex.core.types import SymbolicValue
import z3

def test_cow_dict_hash_consistency():
    d1 = CowDict({"x": 10, "y": 20})
    d2 = CowDict({"y": 10, "x": 20})
    
    h1 = d1.hash_value()
    h2 = d2.hash_value()
    
    # Should not collide because of polynomial hashing (avoiding XOR commutativity)
    assert h1 != h2

def test_cow_dict_symbolic_hash():
    s1, _ = SymbolicValue.symbolic("sym1")
    s2, _ = SymbolicValue.symbolic("sym2")
    
    d1 = CowDict({"a": s1})
    d2 = CowDict({"a": s2})
    
    assert d1.hash_value() != d2.hash_value()

    # Same symbolic value should hash same
    d3 = CowDict({"a": s1})
    assert d1.hash_value() == d3.hash_value()
    
def test_cow_dict_large_scale():
    # Insert many elements, test for unexpected collisions
    hashes = set()
    for i in range(100):
        d = CowDict({f"key_{j}": j * i for j in range(50)})
        hashes.add(d.hash_value())
    
    # All 100 dicts are distinct, should have 100 unique hashes
    assert len(hashes) == 100

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
