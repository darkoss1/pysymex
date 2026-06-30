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

"""Path-feasibility telemetry records.

This module owns passive diagnostic records emitted by the execution-facing
path-feasibility policy. These records are observational only: they do not
participate in pruning, solver calls, detector publication, or caching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Sequence

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession

PathFeasibilityResult = Literal["feasible", "infeasible", "inconclusive"]
"""Closed set of path-feasibility outcomes exposed in trace output."""

PathFeasibilityResultSource = Literal[
    "literal_true",
    "literal_false",
    "simplified_false",
    "literal_substitution_false",
    "literal_substitution_true",
    "hard_theory_witness",
    "hard_theory_skipped",
    "solver_sat",
    "solver_unsat",
    "solver_unknown",
]
"""Closed set of path-feasibility decision sources used in trace output."""

_MAX_PATH_FEASIBILITY_CONSTRAINT_EXCERPT = 8


@dataclass(frozen=True, slots=True)
class PathFeasibilityEvent:
    """Bounded diagnostic outcome for one pending path-feasibility check."""

    path_id: int
    pc: int | None
    line_number: int | None
    pending_constraint_count: int
    path_constraints_count: int
    known_sat_prefix_len: int
    query_prefix_len: int
    query_constraints_count: int
    result: PathFeasibilityResult
    result_source: PathFeasibilityResultSource
    solver_called: bool
    hard_theory_skipped: bool
    policy_latency_ms: float
    query_constraint_excerpt: tuple[z3.BoolRef, ...] = ()


def emit_path_feasibility_event(
    *,
    session: ExecutionSession,
    state: VMState,
    pending_constraint_count: int,
    path_constraints_count: int,
    known_sat_prefix_len: int,
    query_prefix_len: int,
    query_constraints_count: int,
    result: PathFeasibilityResult | None,
    result_source: PathFeasibilityResultSource,
    solver_called: bool,
    hard_theory_skipped: bool,
    policy_latency_ms: float,
    query_constraints: Sequence[z3.BoolRef] | None = None,
) -> None:
    """Emit path-feasibility telemetry only when an observer is installed."""
    if result is None or not session.path_feasibility_event_observers:
        return
    session.record_path_feasibility_event(
        PathFeasibilityEvent(
            path_id=state.path_id,
            pc=state.pc,
            line_number=None,
            pending_constraint_count=pending_constraint_count,
            path_constraints_count=path_constraints_count,
            known_sat_prefix_len=known_sat_prefix_len,
            query_prefix_len=query_prefix_len,
            query_constraints_count=query_constraints_count,
            result=result,
            result_source=result_source,
            solver_called=solver_called,
            hard_theory_skipped=hard_theory_skipped,
            policy_latency_ms=round(policy_latency_ms, 3),
            query_constraint_excerpt=_constraint_excerpt(query_constraints),
        ),
    )


def _constraint_excerpt(
    constraints: Sequence[z3.BoolRef] | None,
) -> tuple[z3.BoolRef, ...]:
    """Return the latest query constraints without serializing in execution code."""
    if not constraints:
        return ()
    limit = _MAX_PATH_FEASIBILITY_CONSTRAINT_EXCERPT
    return tuple(constraints[-limit:])
