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

"""Budget-aware Z3 solver construction for detector evidence probes."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Final, cast

import z3

from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.core.solver.engine.configuration import (
    apply_solver_base_config,
    rlimit_for_timeout_ms,
)
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)

# Witness checks are fallback evidence probes. Keep each detached Z3 query short
# so evidence collection cannot overrun the owning scan or detector budget.
EVIDENCE_SOLVER_TIMEOUT_MS: Final = 50
MIN_ACTIVE_EVIDENCE_BUDGET_MS: Final = EVIDENCE_SOLVER_TIMEOUT_MS * 4
_EVIDENCE_SOLVER_CONFIG_FAILURES = (*EVIDENCE_SOLVER_FAILURES, AttributeError)


def create_evidence_solver() -> z3.Solver | None:
    """Return a Z3 solver for a bounded witness query, or ``None`` after timeout."""
    timeout_ms = _evidence_timeout_ms()
    if timeout_ms is None:
        return None
    try:
        solver = z3.Solver()
        apply_solver_base_config(solver, timeout_ms)
        solver.set("rlimit", rlimit_for_timeout_ms(timeout_ms))
    except _EVIDENCE_SOLVER_CONFIG_FAILURES:
        logger.debug("Evidence solver configuration failed; treating as inconclusive")
        return None
    return solver


def evidence_budget_available() -> bool:
    """Return whether a fallback evidence probe may start more Z3 work."""
    return _evidence_timeout_ms() is not None


def _evidence_timeout_ms() -> int | None:
    solver = SolverContext.active.get()
    if solver is None:
        return EVIDENCE_SOLVER_TIMEOUT_MS
    effective_timeout = getattr(solver, "_effective_timeout_ms", None)
    if not callable(effective_timeout):
        return EVIDENCE_SOLVER_TIMEOUT_MS
    try:
        timeout_ms = cast("Callable[[], int]", effective_timeout)()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug("Could not resolve active solver timeout for evidence query")
        return None
    if timeout_ms <= 0:
        return None
    deadline_budget_ms = _active_deadline_budget_ms(solver)
    if deadline_budget_ms is not None and deadline_budget_ms <= MIN_ACTIVE_EVIDENCE_BUDGET_MS:
        return None
    return min(timeout_ms, EVIDENCE_SOLVER_TIMEOUT_MS)


def _active_deadline_budget_ms(solver: object) -> int | None:
    """Return remaining wall-clock budget for an active solver deadline, if set."""
    deadline_time = getattr(solver, "_deadline_time", None)
    if deadline_time is None:
        return None
    if not isinstance(deadline_time, (float, int)):
        return None
    remaining_ms = int((deadline_time - time.perf_counter()) * 1000)
    return max(0, remaining_ms)
