"""Tests for execution fallback classification helpers."""

from __future__ import annotations

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state.record import VMState
from pysymex.core.state.types import VMStateError
from pysymex.execution.fallback import (
    FallbackKind,
    RiskLevel,
    SoundnessTag,
    UNSUPPORTED_VM_STATE_DEGRADED_PASS,
    record_unsupported_vm_state,
)
from pysymex.execution.session.state import ExecutionSession


def test_record_unsupported_vm_state_emits_unknown_issue_and_degraded_pass() -> None:
    session = ExecutionSession()
    state = VMState(pc=4)
    degraded: list[str] = []

    record_unsupported_vm_state(
        session=session,
        state=state,
        exc=VMStateError("unit failure"),
        line_number=12,
        record_degraded_passes=degraded.extend,
    )

    issue = session.issues[-1]
    assert issue.kind is IssueKind.UNKNOWN
    assert issue.message == "Unsupported VM state: unit failure"
    assert issue.constraints == list(state.path_constraints)
    assert issue.pc == 4
    assert issue.line_number == 12
    assert session.last_exception is issue
    assert session.paths_pruned == 1
    assert session.degraded_passes == [UNSUPPORTED_VM_STATE_DEGRADED_PASS]
    assert degraded == [UNSUPPORTED_VM_STATE_DEGRADED_PASS]
    event = session.fallback_events[-1]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_VM_STATE_DEGRADED_PASS
    assert event.owner == "execution.fallback"
    assert event.reason == "unit failure"
    assert event.pc == 4
    assert event.line_number == 12
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.LOW
    assert event.false_negative_risk is RiskLevel.HIGH
