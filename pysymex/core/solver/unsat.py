# pysymex: python symbolic execution & formal verification
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
The helper does not turn SAT or UNKNOWN outcomes into infeasibility evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, cast

import z3

from pysymex.core.solver.engine.configuration import create_configured_solver
from pysymex.logger import get_logger

logger = get_logger(__name__)


class TranslatableZ3Expr(Protocol):
    """Z3 expression surface for context translation."""

    def translate(self, target: z3.Context) -> z3.ExprRef:
        """Return this expression translated into ``target`` context."""
        ...


def _translate_bool_constraint(constraint: z3.BoolRef, target_ctx: z3.Context) -> z3.BoolRef | None:
    """Translate a BoolRef into the target Z3 context."""
    source_ctx: object = getattr(constraint, "ctx", None)
    if source_ctx == target_ctx:
        return constraint
    try:
        translated = cast("TranslatableZ3Expr", constraint).translate(target_ctx)
    except z3.Z3Exception:
        logger.warning("UNSAT core constraint translation failed", exc_info=True)
        return None
    if not isinstance(translated, z3.BoolRef):
        logger.warning("UNSAT core constraint translation produced non-boolean expression")
        return None
    return translated


def _core_indicator_name(index: int, constraint: z3.BoolRef) -> str:
    """Return a deterministic assumption name for one candidate constraint."""
    digest = hashlib.blake2s(constraint.sexpr().encode("utf-8"), digest_size=8).hexdigest()
    return f"_pysymex_core_ind_{index}_{digest}"


@dataclass(frozen=True, slots=True)
class UnsatCoreResult:
    """A sufficient, not necessarily minimal, UNSAT subset witness."""

    core: list[z3.BoolRef]
    core_indices: list[int]
    total_constraints: int

    @property
    def reduction_ratio(self) -> float:
        """Return the fraction of original constraints outside this witness."""
        if self.total_constraints == 0:
            return 0.0
        return 1.0 - len(self.core) / self.total_constraints


def extract_unsat_core(
    constraints: list[z3.BoolRef],
    timeout_ms: int = 5000,
) -> UnsatCoreResult | None:
    """Extract a sufficient unsatisfiable core from a set of constraints.

    Uses Z3's built-in unsat_core() with assumption literals to identify
    which constraints contribute to the UNSAT result. Note: the returned
    core is sufficient but not necessarily minimal.

    Args:
        constraints: Z3 Boolean constraints to check for an unsatisfiable core.
        timeout_ms: Solver timeout in milliseconds.

    Returns:
        An extracted sufficient core, or ``None`` when UNSAT is not
        established, including SAT, UNKNOWN, and translation-failure cases.
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
        logger.warning("UNSAT core extraction skipped; no constraints translated")
        return None

    solver = create_configured_solver(timeout_ms)

    indicators = [
        z3.Bool(_core_indicator_name(i, c)) for i, (_, c) in enumerate(translated_constraints)
    ]
    assumptions: list[z3.BoolRef] = []

    for ind, (_, c) in zip(indicators, translated_constraints, strict=False):
        try:
            solver.add(z3.Implies(ind, c))
            assumptions.append(ind)
        except z3.Z3Exception:
            logger.warning("UNSAT core assumption construction failed", exc_info=True)
            continue

    if not assumptions:
        logger.warning("UNSAT core extraction skipped; no assumptions constructed")
        return None

    try:
        result = solver.check(*assumptions)
    except (z3.Z3Exception, OSError, RuntimeError, ValueError):
        logger.warning("UNSAT core solver check failed", exc_info=True)
        return None

    if result != z3.unsat:
        if logger.state.trace_enabled:
            logger.trace("UNSAT core extraction returned %s", result)
        return None

    try:
        core_indicators = solver.unsat_core()
    except (z3.Z3Exception, OSError, RuntimeError, ValueError):
        logger.warning("UNSAT core extraction failed", exc_info=True)
        return None
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


def prune_with_core(
    constraints: list[z3.BoolRef],
    core_result: UnsatCoreResult,
) -> list[z3.BoolRef]:
    """Keep only constraints selected by an extracted UNSAT core.

    The supplied core is sufficient for infeasibility but is not promised to
    be minimal.

    Args:
        constraints: Original full constraint list.
        core_result: Result from extract_unsat_core().

    Returns:
        Pruned list containing only core constraints.
    """
    core_set = set(core_result.core_indices)
    return [c for i, c in enumerate(constraints) if i in core_set]
