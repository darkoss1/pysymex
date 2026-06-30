"""Shared helpers for solver engine tests."""

from __future__ import annotations

import z3


def is_sat_with_z3(constraints: list[z3.BoolRef]) -> bool:
    """Return whether the given constraints are satisfiable in raw Z3."""
    solver = z3.Solver()
    solver.add(constraints)
    return solver.check() == z3.sat
