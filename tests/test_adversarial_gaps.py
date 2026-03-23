"""
Tests exposing adversarial vulnerabilities and soundness gaps in the symbolic execution engine.

These tests are expected to fail (XFAIL) until the underlying gaps are patched.
Invariants are explicitly documented in each test's docstring.
"""

import pytest
import z3

from pysymex.api import analyze
from pysymex.core.types import SymbolicValue
from pysymex.core.symbolic_types_containers import SymbolicString
from pysymex.core.symbolic_types_numeric import SymbolicInt


@pytest.mark.xfail(strict=True, reason="Gap 1: Bitwise Truncation silently wraps 64-bit bounds")
def test_bitwise_truncation_vulnerability():
    """
    Invariant: Python arbitrary precision integers should not silently truncate on bitwise operations.
    Vulnerability: SymbolicInt maps to 64-bit BitVecs, causing silent truncation for values > 2**64.
    """
    x = SymbolicInt(z3.Int("x"))
    large_val = SymbolicInt(z3.IntVal(2**65))
    
    # Perform bitwise AND with a value larger than 64 bits
    result = x & large_val
    
    solver = z3.Solver()
    # If x is 2**65, x & 2**65 should be 2**65, which is > 0.
    solver.add(x.z3_int == 2**65)
    solver.add(result.z3_int > 0)
    
    # A sound engine preserves arbitrary precision, so result > 0 is SAT.
    # A vulnerable engine truncates 2**65 to 0, so x & 0 == 0. 0 > 0 is UNSAT.
    assert solver.check() == z3.sat, "Engine failed to maintain arbitrary precision (truncated 2**65 to 0)"


@pytest.mark.xfail(strict=True, reason="Gap 2: list.__add__ yields fresh elements instead of constrained structures")
def test_container_precision_loss():
    """
    Invariant: Appending or updating containers must propagate content constraints.
    Vulnerability: list.__add__ returns a fresh unconstrained length array.
    """
    def list_add_test(lst):
        if len(lst) == 0:
            lst2 = lst + [1]
            if len(lst2) != 1:
                return 1 / 0  # Erroneously reachable if precision is lost
        return 0

    res = analyze(list_add_test, {"lst": "list"})
    assert not res.has_issues(), "Container operation lost precision, resulting in false-positive infeasible path"


@pytest.mark.xfail(strict=True, reason="Gap 3: String multiplication by symbolic int yields unconstrained string")
def test_string_multiplication_unconstrained():
    """
    Invariant: String multiplication by N should retain content and length properties (e.g. len = len(s) * N).
    Vulnerability: Multiplying by a symbolic integer returns a fresh string `strmul_...` with no length bounds.
    """
    s = SymbolicString.concrete("abc")
    n = SymbolicInt(z3.Int("n"))
    
    # Multiply by symbolic n
    result = s * n
    
    solver = z3.Solver()
    # Assume n == 2
    solver.add(n.z3_int == 2)
    # A precise engine knows result length is exactly 6
    solver.add(result.length().z3_int != 6)
    
    # For a sound engine, length != 6 is UNSAT.
    # For the vulnerable engine, result length is unconstrained, so it evaluates to SAT.
    assert solver.check() == z3.unsat, "String multiplication lost length constraints"


@pytest.mark.xfail(strict=True, reason="Gap 4: CHECK_EXC_MATCH returns unconstrained boolean for symbolic exceptions")
def test_exception_type_confusion():
    """
    Invariant: CHECK_EXC_MATCH should respect the Python exception class hierarchy.
    Vulnerability: It yields an unconstrained bool, allowing `except ValueError` to catch `TypeError`.
    """
    def catch_wrong_type(x):
        try:
            if x > 0:
                raise TypeError("Type Error!")
        except ValueError:
            # Reached erroneously because CHECK_EXC_MATCH forks execution unconditionally
            return 1 / 0
        return 0

    res = analyze(catch_wrong_type, {"x": "int"})
    assert not res.has_issues(), "Exception handler caught unrelated exception type (TypeError caught by ValueError)"


@pytest.mark.xfail(strict=False, reason="Gap 5 monitor: may be fixed depending on heuristics")
def test_z3_heuristic_bypass():
    """
    Invariant: Div-by-zero checks should apply to all runtime objects unless statically proven safe.
    Vulnerability: The division heuristic bypasses checks if the operand's class name contains 'z3'.
    """
    class z3_mock_int(int):
        pass
    
    def divide_by_z3_mock():
        zero = z3_mock_int(0)
        return 100 / zero

    res = analyze(divide_by_z3_mock, {})
    
    # Sound engine detects division by zero. Vulnerable engine ignores it.
    assert res.has_issues(), "Division-by-zero detector bypassed by adversarial class name containing 'z3'"


@pytest.mark.xfail(strict=False, reason="Gap 6 monitor: may be fixed depending on type handling")
def test_list_indexing_type_error_masking():
    """
    Invariant: Indexing a list with a string should trigger a runtime TypeError.
    Vulnerability: The engine forces an `is_int` constraint, making the path UNSAT and silencing the error.
    """
    def index_with_str(lst):
        return lst["adversarial"]
        
    res = analyze(index_with_str, {"lst": "list"})
    
    # A sound engine should detect a type error. A vulnerable engine hides it (0 issues).
    assert res.has_issues(), "List indexed by string failed to trigger TypeError (path was silently marked UNSAT)"


@pytest.mark.xfail(strict=False, reason="Gap 7 monitor: may be fixed depending on iterator modeling")
def test_dict_iteration_unconstrained():
    """
    Invariant: Iterating a dict must yield keys that are actually present in the dict's known_keys.
    Vulnerability: GET_ITER yields unconstrained keys, allowing them to take values not in the dict.
    """
    def iterate_dict(d):
        for k in d:
            if k not in d:
                # Erroneously reachable due to unconstrained keys
                return 1 / 0
        return 0

    res = analyze(iterate_dict, {"d": "dict"})
    assert not res.has_issues(), "Dict iteration yielded a key not verified to be present in the dict"
