"""Tests for execution-session degraded-pass ownership."""

from __future__ import annotations

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.detectors.telemetry import DetectorQueryEvent
from pysymex._internal.execution.fallback.types import FallbackEvent, FallbackKind
from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex._internal.execution.session.events import (
    add_unique_observer,
    event_with_resolved_line,
    notify_observers,
)
from pysymex._internal.execution.session.lifecycle import SessionLifecycleMixin
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.session.telemetry import SessionTelemetryMixin


def test_session_event_helpers_use_direct_owners() -> None:
    assert add_unique_observer is add_unique_observer
    assert event_with_resolved_line is event_with_resolved_line
    assert notify_observers is notify_observers
    assert issubclass(ExecutionSession, SessionLifecycleMixin)
    assert issubclass(ExecutionSession, SessionTelemetryMixin)


def test_reset_for_run_preserves_infrastructure_degradation_and_clears_run_state() -> None:
    session = ExecutionSession()
    session.issues.append(Issue(kind=IssueKind.UNKNOWN, message="unit"))
    session.coverage.add(4)
    session.phase_counts["execute_step"] = 9
    session.last_stack.append("value")
    session.detector_query_cache_hits = 3

    session.reset_for_run(["infrastructure_unavailable"])

    assert session.issues == []
    assert session.coverage == set()
    assert session.paths_explored == 1
    assert session.degraded_passes == ["infrastructure_unavailable"]
    assert session.phase_counts["execute_step"] == 0
    assert session.last_stack == []
    assert session.detector_query_cache_hits == 0


def test_record_degraded_passes_preserves_first_seen_order_without_duplicates() -> None:
    session = ExecutionSession()

    session.record_degraded_passes(["solver_unknown", "path_limit"])
    session.record_degraded_passes(["solver_unknown", "unsupported_vm_state"])

    assert session.degraded_passes == [
        "solver_unknown",
        "path_limit",
        "unsupported_vm_state",
    ]


def test_record_fallback_event_preserves_event_and_degraded_label_compatibility() -> None:
    session = ExecutionSession()

    first = FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label="unsupported_vm_state",
        owner="execution.fallback",
        reason="first",
    )
    second = FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label="unsupported_vm_state",
        owner="execution.fallback",
        reason="second",
    )

    session.record_fallback_event(first)
    session.record_fallback_event(second)

    assert session.fallback_events == [first, second]
    assert session.degraded_passes == ["unsupported_vm_state"]


def test_record_fallback_event_notifies_observer_once() -> None:
    session = ExecutionSession()
    observed: list[FallbackEvent] = []
    event = FallbackEvent(
        kind=FallbackKind.UNKNOWN,
        label="solver_unknown",
        owner="execution.feasibility",
        reason="solver returned unknown",
    )

    session.add_fallback_event_observer(observed.append)
    session.add_fallback_event_observer(observed.append)
    session.record_fallback_event(event)

    assert observed == [event]


def test_record_fallback_event_observer_failure_does_not_block_recording() -> None:
    session = ExecutionSession()
    event = FallbackEvent(
        kind=FallbackKind.UNKNOWN,
        label="solver_unknown",
        owner="execution.feasibility",
        reason="solver returned unknown",
    )

    def fail(_: FallbackEvent) -> None:
        raise RuntimeError("observer failed")

    session.add_fallback_event_observer(fail)
    session.record_fallback_event(event)

    assert session.fallback_events == [event]
    assert session.degraded_passes == ["solver_unknown"]


def test_record_fallback_event_resolves_source_line_from_pc_mapping() -> None:
    session = ExecutionSession()
    session.pc_to_line[12] = 44

    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label="solver_unknown",
            owner="execution.feasibility",
            reason="solver returned unknown",
            pc=12,
        )
    )

    assert session.fallback_events[0].line_number == 44


def test_record_detector_query_event_notifies_observer_once_and_resolves_line() -> None:
    session = ExecutionSession()
    session.pc_to_line[21] = 88
    observed: list[DetectorQueryEvent] = []
    event = DetectorQueryEvent(
        detector_name="division-by-zero",
        issue_kind="DIVISION_BY_ZERO",
        path_id=3,
        pc=21,
        line_number=None,
        opcode="BINARY_OP",
        raw_constraints_count=4,
        constraints_count=3,
        state_constraints_count=2,
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=-1,
        inconclusive_prefix_len=None,
        result=True,
        result_source="solver_sat",
        cache_hit=False,
        witness_used=False,
    )

    session.add_detector_query_event_observer(observed.append)
    session.add_detector_query_event_observer(observed.append)
    session.record_detector_query_event(event)

    assert len(observed) == 1
    assert observed[0].line_number == 88


def test_record_detector_query_event_observer_failure_does_not_block_recording() -> None:
    session = ExecutionSession()
    observed: list[DetectorQueryEvent] = []
    event = DetectorQueryEvent(
        detector_name="division-by-zero",
        issue_kind="DIVISION_BY_ZERO",
        path_id=3,
        pc=21,
        line_number=88,
        opcode="BINARY_OP",
        raw_constraints_count=4,
        constraints_count=3,
        state_constraints_count=2,
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=-1,
        inconclusive_prefix_len=None,
        result=True,
        result_source="solver_sat",
        cache_hit=False,
        witness_used=False,
    )

    def fail(_: DetectorQueryEvent) -> None:
        raise RuntimeError("observer failed")

    session.add_detector_query_event_observer(fail)
    session.add_detector_query_event_observer(observed.append)
    session.record_detector_query_event(event)

    assert observed == [event]


def test_record_path_feasibility_event_notifies_observer_once_and_resolves_line() -> None:
    session = ExecutionSession()
    session.pc_to_line[31] = 144
    observed: list[PathFeasibilityEvent] = []
    event = PathFeasibilityEvent(
        path_id=5,
        pc=31,
        line_number=None,
        pending_constraint_count=12,
        path_constraints_count=17,
        known_sat_prefix_len=5,
        query_prefix_len=5,
        query_constraints_count=12,
        result="inconclusive",
        result_source="hard_theory_skipped",
        solver_called=False,
        hard_theory_skipped=True,
        policy_latency_ms=0.25,
    )

    session.add_path_feasibility_event_observer(observed.append)
    session.add_path_feasibility_event_observer(observed.append)
    session.record_path_feasibility_event(event)

    assert len(observed) == 1
    assert observed[0].line_number == 144


def test_record_path_feasibility_event_observer_failure_does_not_block_recording() -> None:
    session = ExecutionSession()
    observed: list[PathFeasibilityEvent] = []
    event = PathFeasibilityEvent(
        path_id=5,
        pc=31,
        line_number=144,
        pending_constraint_count=12,
        path_constraints_count=17,
        known_sat_prefix_len=5,
        query_prefix_len=5,
        query_constraints_count=12,
        result="feasible",
        result_source="solver_sat",
        solver_called=True,
        hard_theory_skipped=False,
        policy_latency_ms=0.25,
    )

    def fail(_: PathFeasibilityEvent) -> None:
        raise RuntimeError("observer failed")

    session.add_path_feasibility_event_observer(fail)
    session.add_path_feasibility_event_observer(observed.append)
    session.record_path_feasibility_event(event)

    assert observed == [event]
