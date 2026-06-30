"""Tests for opcode-result issue publication."""

from __future__ import annotations

from typing import cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.detectors.records import DeferredDetectorIssue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.fallback.types import FallbackEvent, FallbackKind
from pysymex._internal.execution.results.routing.fallbacks import emit_opcode_result_fallback_events
from pysymex._internal.execution.results.routing.fallbacks import (
    emit_opcode_result_fallback_events as direct_publish_fallback_events,
)
from pysymex._internal.execution.results.routing.issues import publish_opcode_result_issues
from pysymex._internal.execution.results.routing.issues import (
    publish_opcode_result_issues as direct_publish_issues,
)
from pysymex._internal.execution.results.routing.successors import route_successor_opcode_result
from pysymex._internal.execution.results.routing.successors import (
    route_successor_opcode_result as direct_route_successors,
)
from pysymex._internal.execution.results.routing.terminal import route_terminal_opcode_result
from pysymex._internal.execution.results.routing.terminal import (
    route_terminal_opcode_result as direct_route_terminal,
)
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.strategies.manager.types import PathManager
from pysymex._internal.limits.models import LimitExceeded, ResourceType


class _FakeWorklist(PathManager[VMState]):
    def __init__(self) -> None:
        self.added: list[VMState] = []

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        _ = priority
        self.added.append(state)

    def get_next_state(self) -> VMState | None:
        return self.added.pop(0) if self.added else None

    def is_empty(self) -> bool:
        return not self.added

    def size(self) -> int:
        return len(self.added)


class _RejectAdditionalPathTracker:
    def record_path(self) -> int:
        raise LimitExceeded(ResourceType.PATHS, 2, 2)


def test_result_routing_exports_use_direct_owners() -> None:
    assert emit_opcode_result_fallback_events is direct_publish_fallback_events
    assert publish_opcode_result_issues is direct_publish_issues
    assert route_successor_opcode_result is direct_route_successors
    assert route_terminal_opcode_result is direct_route_terminal


def test_publish_opcode_result_issues_normalizes_line_number_and_fires_hook() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    owner = object()
    seen: list[Issue] = []
    issue = Issue(kind=IssueKind.UNKNOWN, message="unit", pc=3, line_number=None)

    def hook(_owner: object, _state: VMState, published: Issue) -> None:
        seen.append(published)

    publish_opcode_result_issues(
        session=session,
        hook_owner=owner,
        hooks={"on_issue": [hook]},
        result=OpcodeResult(new_states=[], issues=[issue]),
        state=state,
        resolve_line_number=lambda _pc: 42,
    )

    assert session.issues[0].line_number == 42
    assert session.issues[0] is seen[0]
    assert issue.line_number is None


def test_publish_opcode_result_issues_swallow_hook_failures() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    issue = Issue(kind=IssueKind.UNKNOWN, message="unit", pc=3)

    def fail(_owner: object, _state: VMState, _issue: Issue) -> None:
        raise RuntimeError("hook failed")

    publish_opcode_result_issues(
        session=session,
        hook_owner=object(),
        hooks={"on_issue": [fail]},
        result=OpcodeResult(new_states=[], issues=[issue]),
        state=state,
        resolve_line_number=lambda _pc: None,
    )

    assert session.issues == [issue]


def test_publish_opcode_result_fallback_events_records_event_and_degraded_label() -> None:
    session = ExecutionSession()
    event = FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label="unmodeled_call_abstraction",
        owner="execution.calls",
        reason="unit",
    )

    emit_opcode_result_fallback_events(
        session=session,
        result=OpcodeResult(new_states=[], issues=[], fallback_events=[event]),
    )

    assert session.fallback_events == [event]
    assert session.degraded_passes == ["unmodeled_call_abstraction"]


def test_route_terminal_opcode_result_records_terminal_path_and_callback() -> None:
    session = ExecutionSession()
    state = VMState(pc=3, stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    issue = Issue(kind=IssueKind.UNKNOWN, message="unit", pc=3)
    completed: list[int] = []

    consumed = route_terminal_opcode_result(
        session=session,
        hook_owner=object(),
        hooks={},
        result=OpcodeResult(new_states=[], issues=[issue], terminal=True),
        state=state,
        on_path_complete=lambda completed_state: completed.append(completed_state.pc),
    )

    assert consumed is True
    assert session.paths_completed == 1
    assert session.last_stack == [1]
    assert session.last_locals == {"x": 2}
    assert session.last_globals["g"] == 3
    assert session.last_exception is issue
    assert completed == [3]


def test_route_terminal_opcode_result_publishes_deferred_issues_without_degradation() -> None:
    session = ExecutionSession()
    state = VMState(pc=3)
    deferred_issue = Issue(kind=IssueKind.DIVISION_BY_ZERO, message="deferred", pc=2)
    state.deferred_detector_issues = [
        DeferredDetectorIssue(
            deferred_issue, (state.path_id, deferred_issue.pc, deferred_issue.kind)
        )
    ]
    seen: list[Issue] = []

    def hook(_owner: object, _state: VMState, issue: Issue) -> None:
        seen.append(issue)

    consumed = route_terminal_opcode_result(
        session=session,
        hook_owner=object(),
        hooks={"on_issue": [hook]},
        result=OpcodeResult(new_states=[], issues=[], terminal=True),
        state=state,
        on_path_complete=lambda _state: None,
    )

    assert consumed is True
    assert session.issues == [deferred_issue]
    assert seen == [deferred_issue]
    assert state.deferred_detector_issues == []


def test_route_terminal_opcode_result_ignores_nonterminal_result() -> None:
    session = ExecutionSession()

    consumed = route_terminal_opcode_result(
        session=session,
        hook_owner=object(),
        hooks={},
        result=OpcodeResult.continue_with(VMState(pc=1)),
        state=VMState(pc=0),
        on_path_complete=lambda _state: None,
    )

    assert consumed is False
    assert session.paths_completed == 0


def test_route_successor_opcode_result_queues_successors_and_fires_fork_hook() -> None:
    session = ExecutionSession()
    worklist = _FakeWorklist()
    session.worklist = worklist
    parent = VMState(pc=0, depth=4)
    first = VMState(pc=1)
    second = VMState(pc=2)
    explored: list[None] = []
    forks: list[list[VMState]] = []

    def on_fork(_owner: object, _state: VMState, states: list[VMState]) -> None:
        forks.append(states)

    route_successor_opcode_result(
        session=session,
        hook_owner=object(),
        hooks={"on_fork": [on_fork]},
        result=OpcodeResult(new_states=[first, second], issues=[]),
        state=parent,
        resource_tracker=None,
        record_path_explored=lambda: explored.append(None),
    )

    assert worklist.added == [first, second]
    assert first.depth == 5
    assert second.depth == 5
    assert session.paths_explored == 1
    assert explored == [None]
    assert forks == [[first, second]]


def test_route_successor_opcode_result_prunes_additional_path_on_resource_limit() -> None:
    session = ExecutionSession()
    worklist = _FakeWorklist()
    session.worklist = cast("PathManager[VMState]", worklist)
    first = VMState(pc=1)
    second = VMState(pc=2)

    route_successor_opcode_result(
        session=session,
        hook_owner=object(),
        hooks={},
        result=OpcodeResult(new_states=[first, second], issues=[]),
        state=VMState(pc=0),
        resource_tracker=_RejectAdditionalPathTracker(),
        record_path_explored=lambda: None,
    )

    assert worklist.added == [first]
    assert session.paths_pruned == 1
    assert session.degraded_passes == ["resource_limit_paths"]
    event = session.fallback_events[-1]
    assert event.kind is FallbackKind.RESOURCE_LIMIT
    assert event.label == "resource_limit_paths"
    assert event.owner == "execution.resources"
    assert event.pc == 2
