"""Tests for one-step dispatch, hooks, and visit accounting."""

from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.step.dispatch import dispatch_instruction
from pysymex._internal.execution.step.hooks import run_post_step_hooks, run_pre_step_hooks
from pysymex._internal.execution.step.visits import record_instruction_visit


def _instructions(source: str) -> list[dis.Instruction]:
    code = compile(source, "<step-test>", "exec")
    return list(dis.get_instructions(code))


def test_record_instruction_visit_tracks_session_coverage_and_state_visit() -> None:
    session = ExecutionSession()
    state = VMState(pc=7)

    assert record_instruction_visit(session=session, state=state) is False

    assert session.coverage == {7}
    assert 7 in state.visited_pcs


def test_record_instruction_visit_preserves_duplicate_visit_result() -> None:
    session = ExecutionSession()
    state = VMState(pc=7, visited_pcs={7})

    assert record_instruction_visit(session=session, state=state) is True

    assert session.coverage == {7}


def test_run_pre_step_hooks_propagates_hook_failures() -> None:
    owner = object()
    state = VMState()

    def fail(_owner: object, _state: VMState) -> None:
        raise RuntimeError("pre-step failed")

    try:
        run_pre_step_hooks(hook_owner=owner, hooks={"pre_step": [fail]}, state=state)
    except RuntimeError as exc:
        assert str(exc) == "pre-step failed"
    else:
        raise AssertionError("pre-step hook failure was swallowed")


def test_run_post_step_hooks_uses_successor_states() -> None:
    owner = object()
    instr = _instructions("x = 1")[0]
    first = VMState(pc=1)
    second = VMState(pc=2)
    seen: list[int] = []

    def hook(_owner: object, state: VMState, _instr: dis.Instruction) -> None:
        seen.append(state.pc)

    run_post_step_hooks(
        hook_owner=owner,
        hooks={"post_step": [hook]},
        result=OpcodeResult(new_states=[first, second], issues=[]),
        fallback_state=VMState(pc=99),
        instr=instr,
    )

    assert seen == [1, 2]


def test_run_post_step_hooks_uses_fallback_state_for_terminal_result() -> None:
    owner = object()
    instr = _instructions("x = 1")[0]
    state = VMState(pc=99)
    seen: list[int] = []

    def hook(_owner: object, state: VMState, _instr: dis.Instruction) -> None:
        seen.append(state.pc)

    run_post_step_hooks(
        hook_owner=owner,
        hooks={"post_step": [hook]},
        result=OpcodeResult(new_states=[], issues=[], terminal=True),
        fallback_state=state,
        instr=instr,
    )

    assert seen == [99]


def test_dispatch_instruction_skips_snapshots_without_hook_observer() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instr = _instructions("x = 1")[0]
    state = VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    successor = VMState(pc=5)

    def handler(
        _instr: dis.Instruction,
        _state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        return OpcodeResult.continue_with(successor)

    dispatcher.register_handler(instr.opname, handler)

    result = dispatch_instruction(
        dispatcher=dispatcher,
        session=session,
        hook_owner=object(),
        hooks={},
        instr=instr,
        state=state,
    )

    assert result.new_states == [successor]
    assert session.last_stack == []
    assert session.last_locals == {}
    assert session.last_globals == {}


def test_dispatch_instruction_records_snapshots_for_post_step_hook() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instr = _instructions("x = 1")[0]
    state = VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    successor = VMState(pc=5)
    seen_successor_pcs: list[int] = []

    def handler(
        _instr: dis.Instruction,
        _state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        return OpcodeResult.continue_with(successor)

    def hook(_owner: object, hook_state: VMState, _instr: dis.Instruction) -> None:
        seen_successor_pcs.append(hook_state.pc)

    dispatcher.register_handler(instr.opname, handler)

    result = dispatch_instruction(
        dispatcher=dispatcher,
        session=session,
        hook_owner=object(),
        hooks={"post_step": [hook]},
        instr=instr,
        state=state,
    )

    assert result.new_states == [successor]
    assert session.last_stack == [1]
    assert session.last_locals == {"x": 2}
    assert session.last_globals["g"] == 3
    assert seen_successor_pcs == [5]


def test_dispatch_instruction_records_snapshots_for_issue_hook() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instr = _instructions("x = 1")[0]
    state = VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    successor = VMState(pc=5)

    def handler(
        _instr: dis.Instruction,
        _state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        return OpcodeResult.with_issue(
            successor,
            Issue(kind=IssueKind.UNKNOWN, message="unit", pc=0),
        )

    def hook(*_args: object) -> None:
        return None

    dispatcher.register_handler(instr.opname, handler)

    result = dispatch_instruction(
        dispatcher=dispatcher,
        session=session,
        hook_owner=object(),
        hooks={"on_issue": [hook]},
        instr=instr,
        state=state,
    )

    assert result.new_states == [successor]
    assert session.last_stack == [1]
    assert session.last_locals == {"x": 2}
    assert session.last_globals["g"] == 3


def test_dispatch_instruction_records_snapshots_for_fork_hook() -> None:
    session = ExecutionSession()
    dispatcher = OpcodeDispatcher()
    instr = _instructions("x = 1")[0]
    state = VMState(stack=[1], local_vars={"x": 2}, global_vars={"g": 3})
    first = VMState(pc=5)
    second = VMState(pc=6)

    def handler(
        _instr: dis.Instruction,
        _state: VMState,
        _dispatcher: OpcodeDispatcher,
    ) -> OpcodeResult:
        return OpcodeResult.branch([first, second])

    def hook(*_args: object) -> None:
        return None

    dispatcher.register_handler(instr.opname, handler)

    result = dispatch_instruction(
        dispatcher=dispatcher,
        session=session,
        hook_owner=object(),
        hooks={"on_fork": [hook]},
        instr=instr,
        state=state,
    )

    assert result.new_states == [first, second]
    assert session.last_stack == [1]
    assert session.last_locals == {"x": 2}
    assert session.last_globals["g"] == 3
