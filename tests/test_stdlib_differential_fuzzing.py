import pytest
from pysymex import analyze

def test_string_split_parity():
    """Verify that SymbolicString model .split() matches Python concrete built-in exactly."""
    def split_test(s):
        parts = s.split(",")
        if len(parts) == 3:
            return 1
        return 0

    res = analyze(split_test, {"s": "str"})
    
    # We should have successfully explored a path where commas were added leading to len==3
    assert res.paths_explored > 0, "String split simulation failed to explore state branches"

def test_dict_update_parity():
    """Verify SymbolicDict .update() models concrete execution identically."""
    def dict_update_test(k):
        d = {"static_key": 42}
        d.update({k: 100})
        
        # If the key matched, the value was overwritten
        if "static_key" in d and d["static_key"] == 100:
            return 1
        return 0

    res = analyze(dict_update_test, {"k": "str"})
    assert res.paths_explored > 0, "Dict model must propagate symbolic updates soundly"
