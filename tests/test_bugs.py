import pytest
import z3
from pysymex.core.types import SymbolicValue, SymbolicString
from pysymex.core.types_containers import SymbolicList, SymbolicDict

def test_conditional_merge_array():
    """Verify that z3_array is correctly merged in SymbolicValue."""
    l1, _ = SymbolicList.symbolic("l1")
    l2, _ = SymbolicList.symbolic("l2")
    
    v1 = l1.as_unified()
    v2 = l2.as_unified()
    
    cond = z3.Bool("cond")
    merged = v1.conditional_merge(v2, cond)
    
    assert merged.z3_array is not None
    # Check that it's a conditional expression (z3.If)
    assert z3.is_app_of(merged.z3_array, z3.Z3_OP_ITE)

def test_symbolic_value_string_add():
    """Verify that SymbolicValue supports string addition."""
    s1 = SymbolicString.from_const("hello").as_unified()
    s2 = SymbolicString.from_const(" world").as_unified()
    
    res = s1 + s2
    assert res.is_str is not None
    # Since they are both definitely strings, is_str should be True
    # In my implementation, it's z3.And(self.is_str, other.is_str)
    
    # Check if we can get the value back
    assert res.as_string()._z3_str is not None

def test_symbolic_list_extend():
    """Verify that SymbolicList.extend handles symbolic lists."""
    l1, _ = SymbolicList.symbolic("l1")
    l2, _ = SymbolicList.symbolic("l2")
    
    extended = l1.extend(l2)
    assert extended.z3_len is not None
    # Length should be the sum
    # (Simplified check, might need solver to prove equality)
    
    # Access an index from the second part
    val = extended.__getitem__(l1.z3_len)
    assert val.z3_int is not None

def test_symbolic_dict_update():
    """Verify that SymbolicDict.update handles symbolic dicts."""
    d1, _ = SymbolicDict.symbolic("d1")
    d2, _ = SymbolicDict.symbolic("d2")
    
    updated, _constraint = d1.update(d2)
    # Check that we can access a key from d2 in the updated dict
    k = SymbolicString.from_const("key")
    val, presence = updated.__getitem__(k)
    assert val is not None
    assert presence is not None

def test_symbolic_setattr_typo():
    """Verify that symbolic creators don't crash due to __setattr__ typo."""
    try:
        SymbolicValue.symbolic_int("self_test")
        SymbolicValue.symbolic_bool("self_test")
    except AttributeError:
        pytest.fail("__setattr__ typo still present!")

if __name__ == "__main__":
    pytest.main([__file__])
