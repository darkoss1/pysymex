"""Tests for hard-theory execution path-feasibility policy."""

from __future__ import annotations

from unittest.mock import patch

import z3

from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.feasibility.events import (
    SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS,
)
from pysymex._internal.execution.feasibility.literals import (
    literal_substitution_proves,
    literal_substitution_refutes,
)
from pysymex._internal.execution.feasibility.policy import check_path_feasibility
from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex._internal.execution.session.state.core import ExecutionSession
from tests.unit.execution.feasibility.solver_doubles import RecordingSolver


def test_check_path_feasibility_queries_large_bitvector_formula_before_unknown() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=False, result=SolverResult.unknown())
    x = z3.Int("owner_feasibility_hard_x")
    bits = z3.BitVec("owner_feasibility_hard_bits", 8)
    constraints = [x > -100 + index for index in range(29)]
    constraints.append(z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1)
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=99)

    with (
        patch(
            "pysymex._internal.core.solver.constraints.theory.constraints_include_bitvector_smt_theory",
            side_effect=AssertionError("ConstraintChain summary should avoid path rescans"),
        ),
        patch(
            "pysymex._internal.analysis.detectors.feasibility.hard_theory_witness_model",
            return_value=None,
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
    assert solver.checked_constraints == [constraints]
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 99
    assert "solver returned unknown" in session.fallback_events[0].reason
    assert len(observed) == 1
    assert observed[0].result == "inconclusive"
    assert observed[0].result_source == "solver_unknown"
    assert observed[0].solver_called is True
    assert observed[0].hard_theory_skipped is False
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
        *[x + index == index for index in range(11)],
        z3.BV2Int(z3.Int2BV(x, 8), is_signed=False) == 0,
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


def test_check_path_feasibility_accepts_hard_query_true_under_literal_assignments() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=False)
    mode = z3.Int("owner_feasibility_literal_true_mode")
    constraints = [
        mode == 0,
        *[mode >= -index for index in range(29)],
        mode % 2 == 0,
    ]
    state = VMState(path_constraints=constraints, pending_constraint_count=len(constraints), pc=95)

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
    assert observed[0].result_source == "literal_substitution_true"
    assert observed[0].solver_called is False
    assert observed[0].hard_theory_skipped is False


def test_check_path_feasibility_does_not_hard_skip_verified_prefix_theory() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    session.add_path_feasibility_event_observer(observed.append)
    solver = RecordingSolver(feasible=True)
    x = z3.Int("owner_feasibility_verified_prefix_x")
    bits = z3.BitVec("owner_feasibility_verified_prefix_bits", 8)
    prefix = [
        z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1,
        *[x >= -index for index in range(11)],
    ]
    suffix = [x <= 100]
    constraints = [*prefix, *suffix]
    state = VMState(path_constraints=constraints, pending_constraint_count=len(suffix), pc=95)

    result = check_path_feasibility(
        session=session,
        solver=solver,
        hook_owner=object(),
        hooks={},
        state=state,
    )

    assert result is True
    assert solver.checked_constraints == [constraints]
    assert solver.prefix_args == [len(prefix)]
    assert state.pending_constraint_count == 0
    assert session.degraded_passes == []
    assert len(observed) == 1
    assert observed[0].result == "feasible"
    assert observed[0].result_source == "solver_sat"
    assert observed[0].solver_called is True
    assert observed[0].hard_theory_skipped is False


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


def test_literal_substitution_does_not_extract_assignments_from_negated_formula() -> None:
    mode = z3.Int("owner_feasibility_literal_mode")
    item = z3.Int("owner_feasibility_literal_item")

    assert (
        literal_substitution_refutes(
            [
                mode == 0,
                z3.Not(mode == 30),
                (mode * item) % 7 == 0,
            ]
        )
        is False
    )


def test_literal_substitution_proves_true_for_modulo_guard_with_literal_assignment() -> None:
    mode = z3.Int("owner_feasibility_literal_true_guard_mode")

    assert (
        literal_substitution_proves(
            [
                mode == 0,
                z3.Not(mode == 30),
                mode % 2 == 0,
            ]
        )
        is True
    )


def test_check_path_feasibility_queries_medium_bitvector_formula_before_unknown() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False, result=SolverResult.unknown())
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
    assert solver.checked_constraints == [constraints]
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 100


def test_check_path_feasibility_queries_nonlinear_formula_before_unknown() -> None:
    session = ExecutionSession()
    solver = RecordingSolver(feasible=False, result=SolverResult.unknown())
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
    assert solver.checked_constraints == [constraints]
    assert solver.added_constraints == []
    assert state.pending_constraint_count == len(constraints)
    assert state.last_inconclusive_feasibility_len == len(state.path_constraints)
    assert session.paths_pruned == 0
    assert session.degraded_passes == [SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS]
    assert session.fallback_events[0].pc == 101
