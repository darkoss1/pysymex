from __future__ import annotations

import z3

from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


def test_compare_path_is_sat_uses_solver_for_long_nontrivial_contradictions() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"p{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 0]) is False


def test_compare_path_is_sat_keeps_satisfiable_long_paths_feasible() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"q{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 5]) is True
