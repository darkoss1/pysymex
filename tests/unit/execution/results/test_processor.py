"""Tests for opcode-result processing owner."""

from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.results.context import ProcessingContext
from pysymex._internal.execution.results.processor import process_execution_result
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.strategies.manager.types import PathManager


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


def test_process_execution_result_publishes_issue_and_queues_successor() -> None:
    session = ExecutionSession()
    worklist = _FakeWorklist()
    session.worklist = worklist
    parent = VMState(pc=0, depth=4)
    successor = VMState(pc=1)
    issue = Issue(kind=IssueKind.UNKNOWN, message="unit", pc=0)
    seen_issues: list[Issue] = []
    explored: list[None] = []

    def record_issue(_owner: object, _state: VMState, published: Issue) -> None:
        seen_issues.append(published)

    context = ProcessingContext(
        session=session,
        hook_owner=object(),
        hooks={"on_issue": [record_issue]},
        resource_tracker=None,
        resolve_line_number=lambda _pc, _instructions: 42,
        on_path_complete=lambda _state: None,
        record_path_explored=lambda: explored.append(None),
    )
    active_instructions: list[dis.Instruction] = []

    process_execution_result(
        context,
        OpcodeResult(new_states=[successor], issues=[issue]),
        parent,
        active_instructions,
    )

    assert session.phase_counts["process_execution_result"] == 1
    assert session.phase_timers_seconds["process_execution_result"] > 0
    assert session.issues[0].line_number == 42
    assert seen_issues == session.issues
    assert worklist.added == [successor]
    assert successor.depth == 5
    assert explored == []


def test_process_execution_result_routes_terminal_result_once() -> None:
    session = ExecutionSession()
    completed: list[VMState] = []
    state = VMState(pc=3, stack=[1])
    context = ProcessingContext(
        session=session,
        hook_owner=object(),
        hooks={},
        resource_tracker=None,
        resolve_line_number=lambda _pc, _instructions: None,
        on_path_complete=lambda completed_state: completed.append(completed_state),
        record_path_explored=lambda: None,
    )
    active_instructions: list[dis.Instruction] = []

    process_execution_result(
        context,
        OpcodeResult(new_states=[], issues=[], terminal=True),
        state,
        active_instructions,
    )

    assert session.paths_completed == 1
    assert completed == [state]
    assert session.last_stack == [1]
