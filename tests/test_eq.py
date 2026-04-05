from pysymex.core.symbolic_types import SymbolicInt, SymbolicFloat
import z3

def test_eq():
    s_int = SymbolicInt.concrete(5)
    print(f"s_int == 5: {s_int == 5}")
    print(f"s_int == 6: {s_int == 6}")
    
    s_float = SymbolicFloat.concrete(5.0)
    print(f"s_float == 5.0: {s_float == 5.0}")

if __name__ == "__main__":
    test_eq()