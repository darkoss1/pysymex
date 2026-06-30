"""Tests for execution path-feasibility outcome transitions."""

from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.feasibility.outcomes import (
    record_feasible_path,
    record_inconclusive_path,
    record_infeasible_path,
)
from pysymex._internal.execution.feasibility.persistence import persist_verified_constraint_suffix
from pysymex._internal.execution.session.state.core import ExecutionSession
from tests.unit.execution.feasibility.solver_doubles import ExtendingSolver


def test_persist_verified_constraint_suffix_prefers_incremental_path_extension() -> None:
    solver = ExtendingSolver()
    x = z3.Int("owner_feasibility_persist_x")
    suffix_constraint = x > 0

    persist_verified_constraint_suffix(
        solver=solver,
        constraints=[x >= 0, suffix_constraint],
        known_prefix_len=1,
    )

    assert len(solver.extended_constraints) == 1
    assert z3.eq(solver.extended_constraints[0], suffix_constraint)
    assert solver.added_constraints == []


def test_record_infeasible_path_updates_prune_state_and_hooks() -> None:
    session = ExecutionSession()
    state = VMState(pc=12)
    seen_prunes: list[tuple[VMState, str]] = []

    def record_prune(_owner: object, pruned_state: VMState, reason: str) -> None:
        seen_prunes.append((pruned_state, reason))

    record_infeasible_path(
        session=session,
        hook_owner=object(),
        hooks={"on_prune": [record_prune]},
        state=state,
    )

    assert session.paths_pruned == 1
    assert seen_prunes == [(state, "infeasible")]


def test_record_inconclusive_path_preserves_pending_constraints() -> None:
    session = ExecutionSession()
    x = z3.Int("owner_feasibility_inconclusive_x")
    state = VMState(path_constraints=[x > 0], pending_constraint_count=1, pc=13)

    record_inconclusive_path(
        session=session,
        state=state,
        reason="unit inconclusive",
    )

    assert state.pending_constraint_count == 1
    assert state.last_inconclusive_feasibility_len == 1
    assert session.paths_pruned == 0
    assert session.fallback_events[0].reason == "unit inconclusive"


def test_record_feasible_path_persists_verified_suffix_and_clears_pending() -> None:
    solver = ExtendingSolver()
    x = z3.Int("owner_feasibility_outcome_x")
    suffix_constraint = x > 0
    state = VMState(path_constraints=[suffix_constraint], pending_constraint_count=1)
    state.last_inconclusive_feasibility_len = 1

    record_feasible_path(
        solver=solver,
        constraints=[suffix_constraint],
        known_prefix_len=0,
        state=state,
    )

    assert state.pending_constraint_count == 0
    assert state.last_inconclusive_feasibility_len == -1
    assert len(solver.extended_constraints) == 1
    assert z3.eq(solver.extended_constraints[0], suffix_constraint)
