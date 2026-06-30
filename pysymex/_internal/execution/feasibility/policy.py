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

"""Execution-facing path feasibility pruning policy."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.query.planner import symbolic_query
from pysymex._internal.core.state.record import StateConstraints, VMState
from pysymex._internal.execution.feasibility.hard import (
    query_has_hard_theory_witness,
    should_probe_hard_theory_witness,
    skip_hard_theory_pending_query,
)
from pysymex._internal.execution.feasibility.outcomes import (
    record_feasible_path,
    record_inconclusive_path,
    record_infeasible_path,
)
from pysymex._internal.execution.feasibility.pending import (
    normalize_pending_suffix,
)
from pysymex._internal.execution.feasibility.telemetry import (
    PathFeasibilityResult,
    PathFeasibilityResultSource,
    emit_path_feasibility_event,
)

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.execution.feasibility.events import (
        HookMap,
    )
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.typing.protocols import SolverProtocol


def _record_infeasible_path_result(
    *,
    session: ExecutionSession,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
) -> bool:
    """Record an infeasible path and return the pruning decision."""
    record_infeasible_path(
        session=session,
        hook_owner=hook_owner,
        hooks=hooks,
        state=state,
    )
    return False


def _resolve_pending_query_result(
    *,
    solver: SolverProtocol,
    state: VMState,
    query_constraints: list[z3.BoolRef],
    query_prefix_len: int,
    literal_result: bool | None,
) -> tuple[
    SolverResult | None,
    PathFeasibilityResult | None,
    PathFeasibilityResultSource,
    bool,
]:
    """Resolve literal/simplified/hard-theory pending feasibility before final recording."""
    query = symbolic_query(query_constraints)
    if literal_result is False:
        return None, "infeasible", "literal_false", False
    if literal_result is True:
        return None, None, "literal_true", False
    if query.simplifies_to_false():
        return None, "infeasible", "simplified_false", False

    skip_hard_theory_query = skip_hard_theory_pending_query(
        query.hard_theory_probe_constraints(query_prefix_len),
        constraints_have_bitvector_smt_theory=(
            state.path_constraints.has_bitvector_smt_theory() if query_prefix_len == 0 else None
        ),
    )
    if not skip_hard_theory_query:
        return (
            solver.check_sat_result(query_constraints, known_sat_prefix_len=query_prefix_len),
            None,
            "solver_sat",
            True,
        )
    if query.literal_substitution_yields(False):
        return None, "infeasible", "literal_substitution_false", False
    if query.literal_substitution_yields(True):
        return None, None, "literal_substitution_true", False
    if should_probe_hard_theory_witness(query_constraints) and query_has_hard_theory_witness(
        query_constraints,
    ):
        return None, None, "hard_theory_witness", False
    return (
        solver.check_sat_result(query_constraints, known_sat_prefix_len=query_prefix_len),
        None,
        "solver_sat",
        True,
    )


def check_path_feasibility(
    *,
    session: ExecutionSession,
    solver: SolverProtocol,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
) -> bool:
    """Return whether the path remains feasible under its full constraint set."""
    if state.pending_constraint_count <= 0:
        return True

    start = time.perf_counter()
    session.phase_counts["path_feasibility"] += 1
    pending_constraint_count = state.pending_constraint_count
    path_constraints_count = len(state.path_constraints)
    known_prefix_len = 0
    query_prefix_len = 0
    query_constraints_count = 0
    query_constraints: list[z3.BoolRef] = []
    event_result: PathFeasibilityResult | None = None
    event_source: PathFeasibilityResultSource = "solver_sat"
    solver_called = False
    hard_theory_skipped = False
    try:
        known_prefix_len = StateConstraints.known_sat_prefix_len(state)
        constraints = list(state.path_constraints)
        path_constraints_count = len(constraints)
        query_constraints, query_prefix_len, literal_result = normalize_pending_suffix(
            constraints,
            known_prefix_len,
        )
        query_constraints_count = len(query_constraints)
        result, event_result, event_source, solver_called = _resolve_pending_query_result(
            solver=solver,
            state=state,
            query_constraints=query_constraints,
            query_prefix_len=query_prefix_len,
            literal_result=literal_result,
        )
        if event_result == "infeasible":
            return _record_infeasible_path_result(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
            )
        if result is not None and result.is_unsat:
            event_result = "infeasible"
            event_source = "solver_unsat"
            return _record_infeasible_path_result(
                session=session,
                hook_owner=hook_owner,
                hooks=hooks,
                state=state,
            )
        if result is not None and result.is_unknown:
            event_result = "inconclusive"
            event_source = "solver_unknown"
            record_inconclusive_path(
                session=session,
                state=state,
                reason=(
                    "solver returned unknown while checking "
                    f"{state.pending_constraint_count} pending path constraint(s)"
                ),
            )
            return True

        record_feasible_path(
            solver=solver,
            constraints=constraints,
            known_prefix_len=known_prefix_len,
            state=state,
        )
        event_result = "feasible"
        return True
    finally:
        elapsed_seconds = time.perf_counter() - start
        session.phase_timers_seconds["path_feasibility"] += elapsed_seconds
        emit_path_feasibility_event(
            session=session,
            state=state,
            pending_constraint_count=pending_constraint_count,
            path_constraints_count=path_constraints_count,
            known_sat_prefix_len=known_prefix_len,
            query_prefix_len=query_prefix_len,
            query_constraints_count=query_constraints_count,
            result=event_result,
            result_source=event_source,
            solver_called=solver_called,
            hard_theory_skipped=hard_theory_skipped,
            policy_latency_ms=elapsed_seconds * 1000.0,
            query_constraints=query_constraints,
        )
