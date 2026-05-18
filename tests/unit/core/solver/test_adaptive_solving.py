import z3
from pysymex.execution.opcodes.common.control import (
    is_complex_smt_theory,
    branch_feasible,
)


def test_is_complex_smt_theory_simple() -> None:
    """Scenario: Simple linear integer constraints are not classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x > 0) is False
    assert is_complex_smt_theory(x + y == 10) is False
    # Constant multiplication is linear and simple
    assert is_complex_smt_theory(x * 5 == 20) is False


def test_is_complex_smt_theory_fpa() -> None:
    """Scenario: Floating-point constraints are correctly classified as complex SMT theory."""
    # Create Float32 variables/values
    fp_sort = z3.Float32()
    f = z3.FP("f", fp_sort)
    zero = z3.FPVal(0.0, fp_sort)
    assert is_complex_smt_theory(f > zero) is True


def test_is_complex_smt_theory_arrays() -> None:
    """Scenario: Array constraints are correctly classified as complex SMT theory."""
    a = z3.Array("a", z3.IntSort(), z3.IntSort())
    assert is_complex_smt_theory(z3.Select(a, z3.IntVal(0)) == 10) is True


def test_is_complex_smt_theory_nonlinear_div_mod() -> None:
    """Scenario: Division and modulo operations are classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x / y == 2) is True
    assert is_complex_smt_theory(x % y == 1) is True


def test_is_complex_smt_theory_nonlinear_mul() -> None:
    """Scenario: Non-linear variable-variable multiplication is classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x * y == 100) is True


def test_branch_feasible_simple_under_threshold() -> None:
    """Scenario: Simple linear constraint with count under 24; expected solved using SMT."""
    x = z3.Int("x")
    # Path constraint list of 10 items (under threshold 24)
    constraints = [x > i for i in range(10)]
    assert branch_feasible(constraints, x > 15) is True
    assert branch_feasible(constraints, x < -5) is False


def test_branch_feasible_complex_under_threshold() -> None:
    """Scenario: Complex constraint with count under 8; expected solved using SMT."""
    # FPA variable
    fp_sort = z3.Float32()
    f = z3.FP("f", fp_sort)
    zero = z3.FPVal(0.0, fp_sort)
    constraints = [f > zero]
    assert branch_feasible(constraints, f < zero) is False
