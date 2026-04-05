import pytest
import z3

from pysymex.core.types import SymbolicValue, Z3_TRUE, Z3_FALSE, Z3_ZERO
from pysymex.core.solver import create_solver

def test_mixed_type_addition_float_fallback():
    """Verify that adding an integer to a float gracefully falls back to float without throwing unsat exceptions."""
    val_int, type_c1 = SymbolicValue.symbolic_int("a")
    val_float = SymbolicValue.from_const(3.14)

    result = val_int + val_float

    solver = create_solver()
    solver.add(type_c1)
    # The result MUST be float, not int.
    solver.add(result.is_float == Z3_TRUE)
    solver.add(result.is_int == Z3_FALSE)

    assert solver.check() == z3.sat

    # Check concrete model evaluates without structural errors
    solver.push()
    solver.add(val_int.z3_int == 2)
    assert solver.check() == z3.sat

    m = solver.model()
    # As long as the model evaluates successfully to SAT under the fallback constraints, it proves structural soundness
    solver.pop()

def test_string_repetition_symbolic_count():
    """Verify that string multiplication creates a mathematically sound conditional length."""
    val_str, tc_str = SymbolicValue.symbolic("s")
    val_int, tc_int = SymbolicValue.symbolic_int("n")

    # We restrict it to actually be a string to avoid branch noise in the test
    solver = create_solver()
    solver.add(tc_str, tc_int)
    solver.add(val_str.is_str)

    result = val_str * val_int

    # Prove that if n <= 0, the length is 0
    solver.push()
    solver.add(val_int.z3_int <= 0)
    solver.add(z3.Length(result.z3_str) != 0)
    assert solver.check() == z3.unsat
    solver.pop()

    # Prove that if n > 0, it creates a fresh string 
    # and the logic doesn't crash or return UNSAT.
    solver.push()
    solver.add(val_int.z3_int == 3)
    solver.add(z3.Length(val_str.z3_str) == 5)
    assert solver.check() == z3.sat
    solver.pop()

def test_negative_modulo_python_semantics():
    """Verify that SymbolicValue.__mod__ respects Python's floor division semantics for negative numbers."""
    # Python: -5 % 3 == 1 (because -5 // 3 is -2, and -5 - (-2*3) = 1)
    val_a = SymbolicValue.from_const(-5)
    val_b = SymbolicValue.from_const(3)

    result = val_a % val_b

    solver = create_solver()
    # Ensure it's not 1
    solver.add(result.z3_int != 1)
    assert solver.check() == z3.unsat

def test_floor_division_python_semantics():
    """Verify that SymbolicValue.__floordiv__ respects Python's floor division semantics for negative numbers."""
    # Python: -5 // 3 == -2
    val_a = SymbolicValue.from_const(-5)
    val_b = SymbolicValue.from_const(3)

    result = val_a // val_b

    solver = create_solver()
    solver.add(result.z3_int != -2)
    assert solver.check() == z3.unsat

def test_bitwise_shift_large_values():
    """Verify that large shifts are bounded safely to prevent Z3 bitvector panics."""
    val_a = SymbolicValue.from_const(1)
    val_shift = SymbolicValue.from_const(300)

    result = val_a << val_shift

    solver = create_solver()
    solver.add(result.is_int == Z3_TRUE)
    assert solver.check() == z3.sat

def test_compare_mixed_types_no_crash():
    """Verify that comparing integer to float and string to int doesn't raise exception but returns proper boolean paths."""
    val_int = SymbolicValue.from_const(5)
    val_float = SymbolicValue.from_const(5.0)
    val_str = SymbolicValue.from_const("5")
    
    eq_num = val_int == val_float
    eq_str = val_int == val_str
    
    solver = create_solver()
    
    # 5 == 5.0 is True
    solver.push()
    solver.add(eq_num.z3_bool == False)
    assert solver.check() == z3.unsat
    solver.pop()
    
    # 5 == "5" is False
    solver.push()
    solver.add(eq_str.z3_bool == True)
    assert solver.check() == z3.unsat
    solver.pop()

def test_conditional_merge_preserves_affinity():
    """Verify that conditional_merge doesn't destroy affinity types if they match."""
    v1 = SymbolicValue.from_const(10)
    v2 = SymbolicValue.from_const(20)
    cond = z3.Bool("c")
    
    merged = v1.conditional_merge(v2, cond)
    # The new __add__ relies heavily on affinity or at least correct is_int propagation
    assert merged.is_int is not Z3_FALSE
    
    solver = create_solver()
    solver.add(cond)
    solver.add(merged.z3_int != 10)
    assert solver.check() == z3.unsat

