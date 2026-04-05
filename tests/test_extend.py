from pysymex.core.types_containers import SymbolicList
from pysymex.core.types import SymbolicValue
import z3

def test_extend():
    # create empty list
    list1 = SymbolicList.empty("L1")
    
    # create second list
    list2 = SymbolicList.empty("L2")
    
    # We will make list2 symbolic but without concrete items to trigger Lambda branch
    list2._concrete_items = None
    list2.z3_len = z3.IntVal(2)
    # Put some values in list2
    list2.z3_array = z3.Store(list2.z3_array, 0, z3.IntVal(42))
    list2.z3_array = z3.Store(list2.z3_array, 1, z3.IntVal(99))
    
    list1 = list1.append(SymbolicValue.from_const(7))
    list1._concrete_items = None # force lambda branch if self has it? no, extend only checks other._concrete_items
    
    list3 = list1.extend(list2)
    
    # Evaluate list3[0], list3[1], list3[2]
    solver = z3.Solver()
    solver.add(list3.z3_len == 3)
    
    model = solver.check()
    print(model)
    
    # Let's extract values
    v0 = z3.simplify(z3.Select(list3.z3_array, 0))
    v1 = z3.simplify(z3.Select(list3.z3_array, 1))
    v2 = z3.simplify(z3.Select(list3.z3_array, 2))
    
    print(f"v0={v0}, v1={v1}, v2={v2}")

if __name__ == "__main__":
    test_extend()