
import z3
import pytest
from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE

def test_int_float_promotion():
    # 1 + 1.0 should be float 2.0
    sv1 = SymbolicValue.from_const(1)
    sv2 = SymbolicValue.from_const(1.0)
    
    res = sv1 + sv2
    
    # Check discriminators
    solver = z3.Solver()
    solver.add(res.is_float)
    assert solver.check() == z3.sat
    
    solver.push()
    solver.add(res.is_int)
    assert solver.check() == z3.unsat
    solver.pop()
    
    # Check value
    # For float, we check z3_float
    expected_fp = z3.FPVal(2.0, z3.Float64())
    assert solver.check(res.z3_float == expected_fp) == z3.sat

def test_symbolic_merge_promotion():
    # x = 1 if c else 1.0
    c = z3.Bool('c')
    sv_int = SymbolicValue.from_const(1)
    sv_float = SymbolicValue.from_const(1.0)
    
    merged = sv_int.conditional_merge(sv_float, c)
    
    solver = z3.Solver()
    
    # If c is true, it should be int
    solver.push()
    solver.add(c)
    solver.add(z3.Not(merged.is_int))
    assert solver.check() == z3.unsat
    solver.pop()
    
    # If c is false, it should be float
    solver.push()
    solver.add(z3.Not(c))
    solver.add(z3.Not(merged.is_float))
    assert solver.check() == z3.unsat
    solver.pop()

def test_mixed_addition():
    # (If(c, 1, 1.0)) + 1
    c = z3.Bool('c')
    sv_int = SymbolicValue.from_const(1)
    sv_float = SymbolicValue.from_const(1.0)
    merged = sv_int.conditional_merge(sv_float, c)
    
    other = SymbolicValue.from_const(1)
    
    res = merged + other
    
    solver = z3.Solver()
    
    # If c is true, res should be int (1 + 1 = 2)
    solver.push()
    solver.add(c)
    solver.add(z3.Not(res.is_int))
    assert solver.check() == z3.unsat
    solver.pop()
    
    # If c is false, res should be float (1.0 + 1 = 2.0)
    solver.push()
    solver.add(z3.Not(c))
    solver.add(z3.Not(res.is_float))
    assert solver.check() == z3.unsat
    solver.pop()

def test_int_truediv():
    # 1 / 1 should be float 1.0
    sv1 = SymbolicValue.from_const(1)
    sv2 = SymbolicValue.from_const(1)
    
    res = sv1 / sv2
    
    solver = z3.Solver()
    solver.add(res.is_float)
    assert solver.check() == z3.sat
    
    solver.push()
    solver.add(res.is_int)
    assert solver.check() == z3.unsat
    solver.pop()
    
    expected_fp = z3.FPVal(1.0, z3.Float64())
    assert solver.check(res.z3_float == expected_fp) == z3.sat

def test_symbolic_float_value():
    # sv = symbolic('f')
    # if sv is float, it should be able to be 1.5
    sv, constraint = SymbolicValue.symbolic('f')
    
    solver = z3.Solver()
    solver.add(constraint)
    solver.add(sv.is_float)
    
    # We expect this to FAIL if z3_float is not properly initialized in symbolic()
    val = z3.FPVal(1.5, z3.Float64())
    solver.add(sv.z3_float == val)
    
    assert solver.check() == z3.sat

if __name__ == "__main__":
    test_int_float_promotion()
    test_symbolic_merge_promotion()
    test_mixed_addition()
    test_int_truediv()
    test_symbolic_float_value()
    print("All tests passed!")
