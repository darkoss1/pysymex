from pysymex.core.types import SymbolicValue
from pysymex.core.types_containers import SymbolicList
import z3

def test_list_type_loss():
    # create empty list
    my_list = SymbolicList.empty()
    
    # create a symbolic string unified value
    from pysymex.core.types import SymbolicString
    sym_str = SymbolicString.from_const("hello")
    unified_str = sym_str.as_unified()
    
    print(f"unified_str is_str: {unified_str.is_str}")
    
    # append string to list
    my_list = my_list.append(unified_str)
    
    # get string out
    retrieved = my_list[SymbolicValue.from_const(0)]
    
    print(f"retrieved is_str: {retrieved.is_str}")
    print(f"retrieved is_int: {retrieved.is_int}")

if __name__ == "__main__":
    test_list_type_loss()