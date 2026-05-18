# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""UNSAT core extraction for pysymex.

When Z3 returns UNSAT, extracts a sufficient unsatisfiable core
to identify which constraints are responsible for infeasibility.
Note: Z3's unsat_core() is not guaranteed to return a minimal core.
This enables better error messages and faster subsequent queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

import z3

from pysymex.contracts.decorators import ensures, requires


def _is_unsat_core_result(value: object) -> bool:
    return isinstance(value, UnsatCoreResult)


def _is_reduction_ratio(value: object) -> bool:
    return isinstance(value, float) and 0.0 <= value <= 1.0


class _TranslatableZ3Expr(Protocol):
    """Z3 expression surface for context translation."""

    def translate(self, target: z3.Context) -> z3.ExprRef: ...


def _translate_bool_constraint(constraint: z3.BoolRef, target_ctx: z3.Context) -> z3.BoolRef | None:
    """Translate a BoolRef into the target Z3 context."""
    source_ctx: object = getattr(constraint, "ctx", None)
    if source_ctx == target_ctx:
        return constraint
    try:
        translated = cast("_TranslatableZ3Expr", constraint).translate(target_ctx)
    except z3.Z3Exception:
        return None
    return translated if isinstance(translated, z3.BoolRef) else None


@dataclass(frozen=True, slots=True)
class UnsatCoreResult:
    """Result of UNSAT core extraction."""

    core: list[z3.BoolRef]
    core_indices: list[int]
    total_constraints: int

    @property
    @ensures(_is_reduction_ratio)
    def reduction_ratio(self) -> float:
        """Ratio of constraints eliminated (0.0 = no reduction, 1.0 = maximal)."""
        if self.total_constraints == 0:
            return 0.0
        return 1.0 - len(self.core) / self.total_constraints


@requires("len(constraints) >= 0")
@requires("timeout_ms > 0")
def extract_unsat_core(
    constraints: list[z3.BoolRef],
    timeout_ms: int = 5000,
) -> UnsatCoreResult | None:
    """Extract a sufficient unsatisfiable core from a set of constraints.

    Uses Z3's built-in unsat_core() with assumption literals to identify
    which constraints contribute to the UNSAT result. Note: the returned
    core is sufficient but not necessarily minimal.

    Args:
        constraints: List of Z3 boolean constraints known to be UNSAT.
        timeout_ms: Solver timeout in milliseconds.

    Returns:
        UnsatCoreResult with the core constraints, or None if not UNSAT.
    """
    if not constraints:
        return None

    target_ctx = z3.main_ctx()
    translated_constraints: list[tuple[int, z3.BoolRef]] = []
    for index, constraint in enumerate(constraints):
        translated = _translate_bool_constraint(constraint, target_ctx)
        if translated is not None:
            translated_constraints.append((index, translated))

    if not translated_constraints:
        return None

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    indicators = [
        z3.Bool(f"_core_ind_{id(c)}_{i}") for i, (_, c) in enumerate(translated_constraints)
    ]
    assumptions: list[z3.BoolRef] = []

    for ind, (_, c) in zip(indicators, translated_constraints, strict=False):
        try:
            solver.add(z3.Implies(ind, c))
            assumptions.append(ind)
        except z3.Z3Exception:
            continue

    if not assumptions:
        return None

    result = solver.check(*assumptions)

    if result != z3.unsat:
        return None

    core_indicators = solver.unsat_core()
    core_ids = {ind.get_id() for ind in core_indicators}

    core_constraints: list[z3.BoolRef] = []
    core_indices: list[int] = []

    for ind, (original_index, c) in zip(indicators, translated_constraints, strict=False):
        if ind.get_id() in core_ids:
            core_constraints.append(c)
            core_indices.append(original_index)

    return UnsatCoreResult(
        core=core_constraints,
        core_indices=core_indices,
        total_constraints=len(constraints),
    )


@requires("len(constraints) >= 0")
@requires(_is_unsat_core_result)
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
