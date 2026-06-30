"""Tests for one-step path and dispatch snapshots."""

from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import CallFrame, wrap_cow_dict
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.step.snapshots import (
    record_dispatch_snapshots,
    record_terminal_path,
)


def test_record_terminal_path_captures_final_snapshots() -> None:
    session = ExecutionSession()
    state = VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    marker = object()

    record_terminal_path(
        session=session,
        state=state,
        include_stack=True,
        final_exception=marker,
        update_exception=True,
    )

    assert session.paths_completed == 1
    assert session.last_stack == [1]
    assert session.last_locals == {"x": 2}
    assert session.last_globals["g"] == 3
    assert session.last_exception is marker


def test_record_terminal_path_can_preserve_existing_exception_snapshot() -> None:
    session = ExecutionSession()
    marker = object()
    session.last_exception = marker

    record_terminal_path(
        session=session,
        state=VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3}),
        include_stack=False,
    )

    assert session.paths_completed == 1
    assert session.last_stack == []
    assert session.last_exception is marker


def test_record_dispatch_snapshots_prefers_active_call_frame_locals() -> None:
    session = ExecutionSession()
    state = VMState(
        stack=[1],
        local_vars={"outer": 2},
        global_vars={"g": 3},
        call_stack=[CallFrame("callee", 0, wrap_cow_dict({"inner": 4}), 0, ())],
    )

    record_dispatch_snapshots(session=session, state=state)

    assert session.last_stack == [1]
    assert session.last_globals["g"] == 3
    assert session.last_locals == {"inner": 4}


def test_record_dispatch_snapshots_uses_state_locals_without_call_frame() -> None:
    session = ExecutionSession()
    state = VMState(stack=[1], local_vars={"outer": 2}, global_vars={"g": 3})

    record_dispatch_snapshots(session=session, state=state)

    assert session.last_stack == [1]
    assert session.last_globals["g"] == 3
    assert session.last_locals == {"outer": 2}
