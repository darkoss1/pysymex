"""Tests for execution-facing pending-constraint feasibility policy."""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import patch

import z3

from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.execution.feasibility import (
    SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS,
    check_path_feasibility,
    record_pending_constraints_checked,
    should_check_pending_constraints,
)
from pysymex.execution import feasibility as execution_feasibility
from pysymex.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex.execution.session.state import ExecutionSession


class RecordingSolver:
    """Solver double for execution-facing path feasibility tests."""

    def __init__(self, *, feasible: bool, result: SolverResult | None = None) -> None:
        self.result = result or (SolverResult.sat(None) if feasible else SolverResult.unsat())
        self.prefix_args: list[int | None] = []
        self.checked_constraints: list[list[z3.BoolRef]] = []
        self.added_constraints: list[z3.BoolRef] = []

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = assumptions
        _ = need_model
        return self.result

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        self.added_constraints.extend(constraints)

    def reset(self) -> None:
        self.prefix_args = []
        self.checked_constraints = []
        self.added_constraints = []

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = list(constraints)
        self.prefix_args.append(known_sat_prefix_len)
        return not self.result.is_unsat

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        self.checked_constraints.append(list(constraints))
        self.prefix_args.append(known_sat_prefix_len)
        return self.result

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        _ = constraints
        return None

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        _ = constraints
        return self.result

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


def test_should_check_pending_constraints_requires_positive_pending_count() -> None:
    state = VMState(pending_constraint_count=0)

    assert (
        should_check_pending_constraints(
            state=state,
            lazy_eval_threshold=0,
        )
        is False
    )


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


def test_check_path_feasibility_skips_large_bitvector_query_as_degraded_unknown() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=False)
    x = z3.Int("owner_feasibility_hard_x")
    bits = z3.BitVec("owner_feasibility_hard_bits", 8)
    constraints = [x > -100 + index for index in range(29)]
    constraints.append(z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1)
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=99)

    with (
        patch.object(
            execution_feasibility,
            "constraints_include_bitvector_smt_theory",
            side_effect=AssertionError("ConstraintChain summary should avoid path rescans"),
        ),
        patch.object(
            execution_feasibility,
            "hard_theory_witness_model",
            side_effect=AssertionError("large hard queries should skip witness probing"),
        ),
    ):
        result = check_path_feasibility(
            session=session,
            solver=solver,
            hook_owner=object(),
            hooks={},
            state=state,
        )

    assert result is True
    assert solver.checked_constraints == []
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 99
    assert "skipped hard SMT-theory" in session.fallback_events[0].reason
    assert len(observed) == 1
    assert observed[0].result == "inconclusive"
    assert observed[0].result_source == "hard_theory_skipped"
    assert observed[0].solver_called is False
    assert observed[0].hard_theory_skipped is True
    assert 1 <= len(observed[0].query_constraint_excerpt) <= 8
    assert any(
        z3.eq(constraint, constraints[-1]) for constraint in observed[0].query_constraint_excerpt
    )


def test_check_path_feasibility_accepts_hard_query_with_verified_witness() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=False)
    x = z3.Int("owner_feasibility_hard_witness_x")
    constraints = [
        x == 0,
        z3.BV2Int(z3.Int2BV(x, 8), is_signed=False) == 0,
        *[x + index == index for index in range(10)],
    ]
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=96)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.checked_constraints == []
    assert len(solver.added_constraints) == len(constraints)
    assert state.pending_constraint_count == 0
    assert state.last_inconclusive_feasibility_len == -1
    assert session.degraded_passes == []
    assert len(observed) == 1
    assert observed[0].result == "feasible"
    assert observed[0].result_source == "hard_theory_witness"
    assert observed[0].solver_called is False
    assert observed[0].hard_theory_skipped is False
    assert 1 <= len(observed[0].query_constraint_excerpt) <= 8


def test_check_path_feasibility_prunes_simplified_false_hard_query() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=True)
    x = z3.Int("owner_feasibility_hard_false_x")
    bits = z3.BitVec("owner_feasibility_hard_false_bits", 8)
    constraints = [x > -100 + index for index in range(10)]
    constraints.extend(
        [
            z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1,
            x == 0,
            z3.Not(x == 0),
        ]
    )
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=98)

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
    assert session.degraded_passes == []


def test_check_path_feasibility_prunes_hard_query_false_under_literal_assignments() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=True)
    x = z3.Int("owner_feasibility_literal_hard_x")
    y = z3.Int("owner_feasibility_literal_hard_y")
    constraints = [
        x == 0,
        y == 0,
        *[x >= -index for index in range(9)],
        (x * y) % 5 == 2,
    ]
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=97)

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
    assert session.degraded_passes == []


def test_check_path_feasibility_skips_medium_bitvector_query_as_degraded_unknown() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False)
    x = z3.Int("owner_feasibility_medium_hard_x")
    bits = z3.BitVec("owner_feasibility_medium_hard_bits", 8)
    constraints = [x > -10 + index for index in range(11)]
    constraints.append(z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1)
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=100)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.checked_constraints == []
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 100


def test_check_path_feasibility_skips_nonlinear_query_as_degraded_unknown() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False)
    x = z3.Int("owner_feasibility_nonlinear_x")
    y = z3.Int("owner_feasibility_nonlinear_y")
    constraints = [x > -10 + index for index in range(11)]
    constraints.append((x * y) % 7 == 3)
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=101)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.checked_constraints == []
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 101
