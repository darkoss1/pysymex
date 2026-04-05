from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE
import z3

def test_bool_add():
    val1 = SymbolicValue.from_const(True)
    val2 = SymbolicValue.from_const(1)
    
    res = val1 + val2
    
    solver = z3.Solver()
    solver.add(res.is_int == Z3_TRUE)
    print(f"Is result an int? {solver.check() == z3.sat}")
    print(f"res.is_int: {res.is_int}")

if __name__ == "__main__":
    test_bool_add()