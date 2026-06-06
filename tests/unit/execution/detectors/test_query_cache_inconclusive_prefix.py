from __future__ import annotations

import z3

from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.detectors import (
    DetectorQueryContext,
    DetectorQueryEvent,
    SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS,
)
from pysymex.execution.detectors.query.cache import detector_query_is_sat
from pysymex.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_executor_helpers import UnknownSolver


def test_detector_feasibility_skips_solver_for_exact_inconclusive_path_prefix() -> None:
    """An exact already-inconclusive path prefix cannot support a definite detector issue."""
    executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
    unknown_solver = UnknownSolver()
    executor.solver = unknown_solver
    prefix = z3.Bool("detector_inconclusive_prefix")

    result = detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[prefix],
        inconclusive_path_prefix=(prefix,),
    )

    assert result is False
    assert unknown_solver.prefix_args == []
    assert executor.session.degraded_passes == [SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS]
    assert executor.session.fallback_events[-1].reason == (
        "detector query extends an inconclusive path-feasibility prefix with 1 constraint(s)"
    )


def test_detector_feasibility_records_unknown_for_extended_inconclusive_path_prefix() -> None:
    """Detector-specific constraints do not replay an already-inconclusive prefix."""
    executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
    observed: list[DetectorQueryEvent] = []
    unknown_solver = UnknownSolver()
    executor.solver = unknown_solver
    executor.session.add_detector_query_event_observer(observed.append)
    prefix = z3.Bool("detector_extended_inconclusive_prefix")
    extra = z3.Bool("detector_extended_extra")

    result = detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[prefix, extra],
        inconclusive_path_prefix=(prefix,),
    )

    assert result is False
    assert unknown_solver.prefix_args == []
    assert executor.session.degraded_passes == [SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS]
    assert len(observed) == 1
    assert observed[0].result_source == "inconclusive_prefix_unknown"
    assert observed[0].witness_used is False


def test_detector_feasibility_accepts_witness_for_inconclusive_path_prefix() -> None:
    """A complete concrete witness may still prove SAT without the general solver."""
    executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
    unknown_solver = UnknownSolver()
    executor.solver = unknown_solver
    x = z3.Int("detector_inconclusive_witness_x")
    prefix = x == 0

    result = detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[prefix, x + 1 == 1],
        inconclusive_path_prefix=(prefix,),
    )

    assert result is True
    assert unknown_solver.prefix_args == []
    assert executor.session.degraded_passes == []


def test_detector_feasibility_emits_bounded_unknown_query_telemetry() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
    observed: list[DetectorQueryEvent] = []
    unknown_solver = UnknownSolver()
    executor.solver = unknown_solver
    executor.session.add_detector_query_event_observer(observed.append)
    query_context = DetectorQueryContext(
        detector_name="unit-detector",
        issue_kind="TYPE_ERROR",
        path_id=7,
        pc=31,
        line_number=55,
        opcode="BINARY_OP",
        state_constraints_count=3,
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=-1,
    )

    result = detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[z3.Bool("detector_unknown_telemetry")],
        query_context=query_context,
    )

    assert result is False
    assert len(observed) == 1
    assert observed[0].detector_name == "unit-detector"
    assert observed[0].issue_kind == "TYPE_ERROR"
    assert observed[0].path_id == 7
    assert observed[0].pc == 31
    assert observed[0].line_number == 55
    assert observed[0].opcode == "BINARY_OP"
    assert observed[0].raw_constraints_count == 1
    assert observed[0].constraints_count == 1
    assert observed[0].state_constraints_count == 3
    assert observed[0].pending_constraint_count == 1
    assert observed[0].last_inconclusive_feasibility_len == -1
    assert observed[0].inconclusive_prefix_len is None
    assert observed[0].result is False
    assert observed[0].result_source == "solver_unknown"
    assert observed[0].cache_hit is False
    assert observed[0].witness_used is False
    assert len(observed[0].constraint_excerpt) == 1
    assert str(observed[0].constraint_excerpt[0]) == "detector_unknown_telemetry"


def test_detector_feasibility_emits_cache_hit_query_telemetry() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
    observed: list[DetectorQueryEvent] = []
    executor.session.add_detector_query_event_observer(observed.append)
    x = z3.Int("detector_cache_telemetry_x")

    assert detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[x > 0],
        query_context=DetectorQueryContext(detector_name="first", issue_kind="UNKNOWN"),
    )
    assert detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=[x > 0],
        query_context=DetectorQueryContext(detector_name="second", issue_kind="UNKNOWN"),
    )

    assert [event.result_source for event in observed] == ["solver_sat", "cache_hit"]
    assert observed[1].detector_name == "second"
    assert observed[1].result is True
    assert observed[1].cache_hit is True
    assert len(observed[1].constraint_excerpt) == 1
    assert z3.eq(observed[1].constraint_excerpt[0], x > 0)
