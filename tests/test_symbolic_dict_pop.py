from pysymex.core.collections_mapping import SymbolicDictOps
from pysymex.core.memory_model_core import SymbolicMap
from pysymex.core.symbolic_types import SymbolicInt
import z3

def test_dict_pop():
    sm = SymbolicMap("test_map", z3.IntSort(), z3.IntSort())
    # Try popping a key without providing a default
    key = z3.Int("k")
    
    # We are calling pop without a default
    res = SymbolicDictOps.pop(sm, key)
    
    print(f"Constraints on pop: {res.constraints}")

if __name__ == "__main__":
    test_dict_pop()