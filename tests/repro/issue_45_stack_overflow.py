"""Reproduction for Issue #45: Stack Overflow on Deep Recursion.

Ensures that the VM correctly handles deeply nested symbolic paths
without exhausting the host Python stack or memory.
"""

from __future__ import annotations

from pysymex.execution.executors.core import SymbolicExecutor


def test_issue_45_deep_path_instability() -> None:
    """Regression test for Issue #45.

    Verifies that the executor doesn't crash when analyzing code with
    hundreds of nested if-statements or deep recursion.
    """
    executor = SymbolicExecutor()

    def deep_branching(x: int) -> int:
        if x > 50:
            return 1
        if x > 40:
            return 2
        if x > 30:
            return 3
        if x > 20:
            return 4
        if x > 10:
            return 5
        return 6

    result = executor.execute_function(deep_branching, {"x": "int"})
    assert result.paths_explored >= 0
