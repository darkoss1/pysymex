"""Tests for execution-facing pending-constraint feasibility policy."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.feasibility.events import (
    SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS,
)
from pysymex._internal.execution.feasibility.pending import (
    record_pending_constraints_checked,
    should_check_pending_constraints,
)
from pysymex._internal.execution.feasibility.policy import check_path_feasibility
from pysymex._internal.execution.feasibility.policy import (
    check_path_feasibility as check_path_feasibility_export,
)
from pysymex._internal.execution.feasibility.policy import (
    check_path_feasibility as check_path_feasibility_owner,
)
from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex._internal.execution.session.state.core import ExecutionSession
from tests.unit.execution.feasibility.solver_doubles import RecordingSolver


def test_should_check_pending_constraints_requires_positive_pending_count() -> None:
    state = VMState(pending_constraint_count=0)

    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=0,
        )
        is False
    )


def test_check_path_feasibility_public_export_points_to_direct_owner() -> None:
    assert check_path_feasibility_export is check_path_feasibility_owner


def test_should_check_pending_constraints_uses_lazy_threshold() -> None:
    state = VMState(pending_constraint_count=2)

    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=3,
        )
        is False
    )
    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=2,
        )
        is True
    )


def test_should_check_pending_constraints_skips_repeated_inconclusive_attempt() -> None:
    x = z3.Int("owner_feasibility_repeated_unknown_x")
    state = VMState(path_constraints=[x > 0], pending_constraint_count=1)
    state.last_inconclusive_feasibility_len = len(state.path_constraints)

    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=1,
        )
        is False
    )

    state.add_constraint(x < 10)

    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=1,
        )
        is True
    )


def test_record_pending_constraints_checked_clears_pending_count() -> None:
    state = VMState(pending_constraint_count=4)

    record_pending_constraints_checked(state)

    assert state.pending_constraint_count == 0


def test_check_path_feasibility_skips_solver_without_pending_constraints() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False)
    state = VMState(pending_constraint_count=0)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.prefix_args == []
    assert session.phase_counts["path_feasibility"] == 0


def test_check_path_feasibility_prunes_infeasible_path_and_notifies_hook() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False)
    x = z3.Int("owner_feasibility_x")
    state = VMState(path_constraints=[x > 0, x < 0], pending_constraint_count=2)
    seen_prunes: list[tuple[VMState, str]] = []

    def record_prune(_owner: object, pruned_state: VMState, reason: str) -> None:
        seen_prunes.append((pruned_state, reason))

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={"on_prune": [record_prune]},
        state=state,
    )

    assert result is False
    assert solver.prefix_args == [0]
    assert session.paths_pruned == 1
    assert seen_prunes == [(state, "infeasible")]
    assert state.pending_constraint_count == 2


def test_check_path_feasibility_persists_verified_constraint_suffix() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=True)
    x = z3.Int("owner_feasibility_prefix_x")
    y = z3.Int("owner_feasibility_suffix_y")
    suffix_constraint = y > 0
    state = VMState(
        path_constraints=[x > 0, suffix_constraint],
        pending_constraint_count=1,
    )

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.prefix_args == [1]
    assert len(solver.added_constraints) == 1
    assert z3.eq(solver.added_constraints[0], suffix_constraint)
    assert state.pending_constraint_count == 0
    assert len(observed) == 1
    assert observed[0].result == "feasible"
    assert observed[0].result_source == "solver_sat"
    assert observed[0].solver_called is True
    assert observed[0].pending_constraint_count == 1
    assert observed[0].query_constraints_count == 2


def test_check_path_feasibility_strips_pending_tautologies_only_from_query() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=True)
    x = z3.Int("owner_feasibility_tautology_x")
    y = z3.Int("owner_feasibility_tautology_y")
    tautology = z3.Not(z3.BoolVal(False))
    suffix_constraint = y > 0
    state = VMState(
        path_constraints=[x > 0, tautology, suffix_constraint],
        pending_constraint_count=2,
    )

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.prefix_args == [1]
    assert len(solver.checked_constraints) == 1
    assert [str(constraint) for constraint in solver.checked_constraints[0]] == [
        str(x > 0),
        str(suffix_constraint),
    ]
    assert len(solver.added_constraints) == 2
    assert z3.eq(solver.added_constraints[0], tautology)
    assert z3.eq(solver.added_constraints[1], suffix_constraint)
    assert state.pending_constraint_count == 0


def test_check_path_feasibility_prunes_pending_literal_false_without_solver() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=True)
    state = VMState(
        path_constraints=[z3.BoolVal(False)],
        pending_constraint_count=1,
    )

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is False
    assert solver.checked_constraints == []
    assert solver.added_constraints == []
    assert session.paths_pruned == 1
    assert state.pending_constraint_count == 1


def test_check_path_feasibility_keeps_unknown_pending_and_records_degraded() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=True, result=SolverResult.unknown())
    x = z3.Int("owner_feasibility_unknown_x")
    state = VMState(path_constraints=[x > 0], pending_constraint_count=1, pc=42)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.prefix_args == [0]
    assert solver.added_constraints == []
    assert state.pending_constraint_count == 1
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].label == SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS
    assert session.fallback_events[0].pc == 42
