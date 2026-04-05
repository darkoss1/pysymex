from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE
import z3

def check_type(res, expected_type):
    solver = z3.Solver()
    if expected_type == "int":
        solver.add(res.is_int == Z3_TRUE)
    elif expected_type == "bool":
        solver.add(res.is_bool == Z3_TRUE)
    elif expected_type == "float":
        solver.add(res.is_float == Z3_TRUE)
    else:
        assert False
    return solver.check() == z3.sat

def test_bool_int_arithmetic():
    val_b1 = SymbolicValue.from_const(True)
    val_b2 = SymbolicValue.from_const(False)
    val_i1 = SymbolicValue.from_const(1)
    val_f1 = SymbolicValue.from_const(1.5)
    
    assert check_type(val_b1 + val_b2, "int"), "bool + bool should be int"
    assert check_type(val_b1 + val_i1, "int"), "bool + int should be int"
    assert check_type(val_b1 - val_i1, "int"), "bool - int should be int"
    assert check_type(val_b1 * val_i1, "int"), "bool * int should be int"
    assert check_type(val_b1 % val_i1, "int"), "bool % int should be int"
    assert check_type(val_b1 // val_i1, "int"), "bool // int should be int"
    
    assert check_type(val_b1 & val_b2, "bool"), "bool & bool should be bool"
    assert check_type(val_b1 | val_b2, "bool"), "bool | bool should be bool"
    assert check_type(val_b1 ^ val_b2, "bool"), "bool ^ bool should be bool"
    
    assert check_type(val_b1 & val_i1, "int"), "bool & int should be int"
    assert check_type(val_b1 | val_i1, "int"), "bool | int should be int"
    assert check_type(val_b1 ^ val_i1, "int"), "bool ^ int should be int"
    
    assert check_type(~val_b1, "int"), "~bool should be int"
    
    assert check_type(val_b1 << val_i1, "int"), "bool << int should be int"
    assert check_type(val_b1 >> val_i1, "int"), "bool >> int should be int"

    assert check_type(val_b1 + val_f1, "float"), "bool + float should be float"

if __name__ == "__main__":
    test_bool_int_arithmetic()
    print("ALL TESTS PASSED")