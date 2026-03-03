"""UNSAT core extraction for pysymex.

When Z3 returns UNSAT, extracts the minimal unsatisfiable core
to identify which constraints are responsible for infeasibility.
This enables better error messages and faster subsequent queries.
"""

from __future__ import annotations


from dataclasses import dataclass


import z3


@dataclass
class UnsatCoreResult:
    """Result of UNSAT core extraction."""

    core: list[z3.BoolRef]

    core_indices: list[int]

    total_constraints: int

    @property
    def reduction_ratio(self) -> float:
        """Ratio of constraints eliminated (0.0 = no reduction, 1.0 = maximal)."""

        if self.total_constraints == 0:
            return 0.0

        return 1.0 - len(self.core) / self.total_constraints


def extract_unsat_core(
    constraints: list[z3.BoolRef],
    timeout_ms: int = 5000,
) -> UnsatCoreResult | None:
    """Extract the minimal unsatisfiable core from a set of constraints.

    Uses Z3's built-in unsat_core() with assumption literals to identify
    which constraints contribute to the UNSAT result.

    Args:
        constraints: List of Z3 boolean constraints known to be UNSAT.
        timeout_ms: Solver timeout in milliseconds.

    Returns:
        UnsatCoreResult with the core constraints, or None if not UNSAT.
    """

    if not constraints:
        return None

    solver = z3.Solver()

    solver.set("timeout", timeout_ms)

    indicators = [z3.Bool(f"_core_ind_{i}") for i in range(len(constraints))]

    for ind, c in zip(indicators, constraints, strict=False):
        try:
            solver.add(z3.Implies(ind, c))

        except Exception:
            continue

    result = solver.check(*indicators)

    if result != z3.unsat:
        return None

    core_indicators = solver.unsat_core()

    core_indicator_strs = {str(ind) for ind in core_indicators}

    core_constraints: list[z3.BoolRef] = []

    core_indices: list[int] = []

    for i, (ind, c) in enumerate(zip(indicators, constraints, strict=False)):
        if str(ind) in core_indicator_strs:
            core_constraints.append(c)

            core_indices.append(i)

    return UnsatCoreResult(
        core=core_constraints,
        core_indices=core_indices,
        total_constraints=len(constraints),
    )


def prune_with_core(
    constraints: list[z3.BoolRef],
    core_result: UnsatCoreResult,
) -> list[z3.BoolRef]:
    """Remove constraints not in the UNSAT core.

    Keeps only the constraints identified as part of the minimal
    unsatisfiable core, reducing the constraint set for faster
    subsequent queries.

    Args:
        constraints: Original full constraint list.
        core_result: Result from extract_unsat_core().

    Returns:
        Pruned list containing only core constraints.
    """

    core_set = set(core_result.core_indices)

    return [c for i, c in enumerate(constraints) if i in core_set]
