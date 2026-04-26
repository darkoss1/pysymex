"""Test-only utility functions for the pysymex test suite.

This module provides common verification patterns and setup shortcuts used
across multiple test subsystems.
"""

from __future__ import annotations

import z3
from pysymex.core.types import SymbolicBool, SymbolicInt


def create_symbolic_int(name: str | None = None) -> SymbolicInt:
    """Helper to create a high-integrity symbolic integer for testing.

    Args:
        name: The unique identifier for the symbolic variable.

    Returns:
        A fully initialized SymbolicInt instance.
    """
    return SymbolicInt.symbolic(name)


def create_symbolic_bool(name: str | None = None) -> SymbolicBool:
    """Helper to create a high-integrity symbolic boolean for testing.

    Args:
        name: The unique identifier for the symbolic variable.

    Returns:
        A fully initialized SymbolicBool instance.
    """
    return SymbolicBool.symbolic(name)


def assert_is_satisfiable(expr: z3.BoolRef) -> None:
    """Strict verification that a Z3 expression is satisfiable.

    Args:
        expr: The Z3 boolean expression to check.

    Raises:
        AssertionError: If the expression is UNSAT or UNKNOWN.
    """
    solver = z3.Solver()
    solver.add(expr)
    result = solver.check()
    assert result == z3.sat, (
        f"Expression was expected to be SAT, but got {result}\nExpression: {expr}"
    )


def assert_is_unsatisfiable(expr: z3.BoolRef) -> None:
    """Strict verification that a Z3 expression is unsatisfiable.

    Args:
        expr: The Z3 boolean expression to check.

    Raises:
        AssertionError: If the expression is SAT or UNKNOWN.
    """
    solver = z3.Solver()
    solver.add(expr)
    result = solver.check()
    assert result == z3.unsat, (
        f"Expression was expected to be UNSAT, but got {result}\nExpression: {expr}"
    )
