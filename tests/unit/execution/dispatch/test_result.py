from __future__ import annotations

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.fallback.types import FallbackEvent, FallbackKind


def test_continue_with() -> None:
    state = VMState()
    result = OpcodeResult.continue_with(state)

    assert result.new_states == [state]


def test_continue_with_preserves_fallback_events() -> None:
    state = VMState()
    event = FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label="unmodeled_call_abstraction",
        owner="execution.calls",
        reason="unit",
    )

    result = OpcodeResult.continue_with(
        state,
        degraded_passes=["unmodeled_call_abstraction"],
        fallback_events=[event],
    )

    assert result.new_states == [state]
    assert result.degraded_passes == ["unmodeled_call_abstraction"]
    assert result.fallback_events == [event]


def test_branch() -> None:
    s1 = VMState()
    s2 = VMState()
    explicit = Issue(kind=IssueKind.VALUE_ERROR, message="v")

    result = OpcodeResult.branch([s1, s2], [explicit])

    assert len(result.new_states) == 2
    assert explicit in result.issues


def test_fork() -> None:
    s1 = VMState()
    s2 = VMState()
    issue = Issue(kind=IssueKind.INDEX_ERROR, message="idx")

    result = OpcodeResult.fork([s1, s2], [issue, None])

    assert result.new_states == [s1, s2]
    assert issue in result.issues


def test_terminate() -> None:
    result = OpcodeResult.terminate()

    assert result.terminal is True
    assert result.new_states == []
    assert result.issues == []


def test_with_issue() -> None:
    state = VMState()
    issue = Issue(kind=IssueKind.DIVISION_BY_ZERO, message="div")

    result = OpcodeResult.with_issue(state, issue)

    assert result.new_states == [state]
    assert result.issues[-1] == issue


def test_error() -> None:
    fatal = Issue(kind=IssueKind.TYPE_ERROR, message="fatal")

    result = OpcodeResult.error(fatal)

    assert result.terminal is True
    assert result.new_states == []
    assert fatal in result.issues
