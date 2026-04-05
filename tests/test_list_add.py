from pysymex.core.types import SymbolicValue
from pysymex.core.types_containers import SymbolicList
import z3

def test_list_add():
    l1 = SymbolicList.from_const([1, 2]).as_unified()
    l2 = SymbolicList.from_const([3, 4]).as_unified()
    
    # Simulate BINARY_ADD which calls +
    l3 = l1 + l2
    
    print(f"l3 is_list: {l3.is_list}")
    print(f"l3 is_int: {l3.is_int}")
    
    # If list addition is ignored, l3 will just be an integer 0 or similar
    
if __name__ == "__main__":
    test_list_add()