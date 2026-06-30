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

"""Caller-facing solver policy predicates."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.queries import check_sat_result
from pysymex._internal.core.solver.facts import PathFactDecision, PathFactPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    import z3


def path_may_be_feasible(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return whether constraints are not established UNSAT.

    Exploration code uses this optimistic predicate: both SAT and UNKNOWN
    return ``True`` so feasible paths are not pruned on inconclusive solver
    answers. Call :func:`~pysymex._internal.core.solver.engine.queries.check_sat_result`
    when UNKNOWN must not be treated as feasible.
    """
    constraint_list = constraints if isinstance(constraints, list) else list(constraints)
    if _active_solver_deadline_expired():
        return True

    fact_decision = PathFactPolicy.classify(
        constraint_list,
        known_sat_prefix_len=known_sat_prefix_len,
        allow_entailed=True,
        allow_prior_entailment=True,
        allow_supported_sat=True,
    )
    if fact_decision is PathFactDecision.UNSAT:
        return False
    if fact_decision in {PathFactDecision.ENTAILED, PathFactDecision.SAT}:
        return True

    result = check_sat_result(
        constraint_list,
        known_sat_prefix_len=known_sat_prefix_len,
    )
    return not result.is_unsat


def _active_solver_deadline_expired() -> bool:
    solver = SolverContext.active.get()
    if solver is None:
        return False
    effective_timeout = getattr(solver, "_effective_timeout_ms", None)
    if not callable(effective_timeout):
        return False
    return cast("Callable[[], int]", effective_timeout)() <= 0
