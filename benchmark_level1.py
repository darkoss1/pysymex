"""
Level 1 Benchmark Test for PySyMex
Basic Branching - Sanity Check

Tests if the engine can handle basic linear arithmetic and branching.
The goal is to find inputs that reach the target assertion.
"""

def level1_basic_branching(x: int, y: int) -> int:
    """
    Basic branching with arithmetic operations.
    Target: Find inputs that trigger the assertion at the end.
    """
    result = x * 2 + y

    if result > 100:
        result = result - 50
    else:
        result = result + 10

    if result == 42:
        # Target assertion - should be reachable
        assert True, "Target reached!"
    return result


def level1_nested_conditions(a: int, b: int, c: int) -> int:
    """
    Nested conditions with arithmetic.
    Target: Find inputs that reach the deepest branch.
    """
    if a > 0:
        if b > 0:
            if c > 0:
                if a + b + c == 100:
                    # Target assertion
                    assert True, "Deep target reached!"
                    result = a * b * c
                    return result
    return 0


def level1_division_guard(x: int, y: int) -> int:
    """
    Division with guard - test basic constraint solving.
    BUG: Division by zero possible when y == 0
    """
    result = x // y  # Bug: no guard for y == 0
    if result == 10:
        assert True, "Division target reached!"
    return result
