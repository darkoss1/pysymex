from pysymex.core.collections_list import SymbolicListOps, OpResult
from pysymex.core.memory_model_core import SymbolicArray
import z3

def test_slice():
    # Create a symbolic array and put some values in it
    arr = SymbolicArray("my_arr", z3.IntSort())
    arr.length = z3.IntVal(3)
    
    # Store some values
    arr = arr.set(0, z3.IntVal(42))
    
    # Slice it
    res = SymbolicListOps.slice(arr, start=0, stop=2)
    new_arr = res.value
    
    # The elements in new_arr should match
    solver = z3.Solver()
    
    solver.push()
    solver.add(new_arr.get(0) == 42)
    print(f"Is new_arr[0] == 42 satisfiable? {solver.check() == z3.sat}")
    solver.pop()
    
    solver.push()
    solver.add(new_arr.get(0) != 42)
    # If it's correctly sliced, this should be unsat (because it MUST be 42).
    # If it's unconstrained (bugged), it will be SAT.
    print(f"Is new_arr[0] != 42 possible? {solver.check() == z3.sat}")
    solver.pop()

if __name__ == "__main__":
    test_slice()