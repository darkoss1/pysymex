"""Tests for one-step instruction fetching."""

from __future__ import annotations

import dis

from pysymex.core.state.record import VMState
from pysymex.core.state.types import CallFrame, wrap_cow_dict
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.session.state import ExecutionSession
from pysymex.execution.step import (
    DUPLICATE_STATE_PRUNE_REASON,
    build_state_key,
    dispatch_instruction,
    fetch_instruction,
    is_branch_or_jump_instruction,
    record_duplicate_branch_state,
    record_dispatch_snapshots,
    record_instruction_visit,
    record_terminal_path,
    run_post_step_hooks,
    run_pre_step_hooks,
)


def _instructions(source: str) -> list[dis.Instruction]:
    code = compile(source, "<step-test>", "exec")
    return list(dis.get_instructions(code))


def _branch_instruction() -> dis.Instruction:
    return next(
        instr for instr in _instructions("if flag:\n    value = 1") if "JUMP" in instr.opname
    )


def test_fetch_instruction_uses_root_instruction_list_by_default() -> None:
    instructions = _instructions("x = 1")
    instr, active = fetch_instruction(VMState(pc=0), instructions)

    assert instr is instructions[0]
    assert active is instructions


def test_fetch_instruction_uses_state_instruction_list_when_typed() -> None:
    root = _instructions("x = 1")
    nested: list[object] = list(_instructions("y = 2"))
    instr, active = fetch_instruction(VMState(pc=0, current_instructions=nested), root)

    assert instr is nested[0]
    assert active is nested


def test_fetch_instruction_falls_back_when_state_instruction_list_is_untyped() -> None:
    root = _instructions("x = 1")
    instr, active = fetch_instruction(VMState(pc=0, current_instructions=[object()]), root)

    assert instr is root[0]
    assert active is root


def test_fetch_instruction_returns_none_at_end_of_instruction_list() -> None:
    instructions = _instructions("x = 1")
    instr, active = fetch_instruction(VMState(pc=len(instructions)), instructions)

    assert instr is None
    assert active is instructions


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


def test_build_state_key_includes_duplicate_pruning_dimensions() -> None:
    state = VMState(
        pc=3,
        stack=[1, 2],
        call_stack=[CallFrame("callee", 0, wrap_cow_dict({}), 0, ())],
    )

    assert build_state_key(state) == (state.hash_value(), 3, 0, 2, 1, 0)


def test_branch_instruction_detection_includes_jump_names() -> None:
    assert is_branch_or_jump_instruction(_branch_instruction()) is True
    assert is_branch_or_jump_instruction(_instructions("x = 1")[0]) is False


def test_record_duplicate_branch_state_tracks_first_branch_state() -> None:
    session = ExecutionSession()
    state = VMState(pc=1)

    pruned = record_duplicate_branch_state(
        session=session,
        state=state,
        instr=_branch_instruction(),
        hook_owner=object(),
        hooks={},
    )

    assert pruned is False
    assert session.paths_pruned == 0
    assert session.visited_states == {build_state_key(state)}


def test_record_duplicate_branch_state_prunes_repeated_branch_state() -> None:
    session = ExecutionSession()
    state = VMState(pc=1)
    instr = _branch_instruction()
    seen_reasons: list[str] = []

    def hook(_owner: object, _state: VMState, reason: str) -> None:
        seen_reasons.append(reason)

    assert (
        record_duplicate_branch_state(
            session=session,
            state=state,
            instr=instr,
            hook_owner=object(),
            hooks={"on_prune": [hook]},
        )
        is False
    )
    assert (
        record_duplicate_branch_state(
            session=session,
            state=state,
            instr=instr,
            hook_owner=object(),
            hooks={"on_prune": [hook]},
        )
        is True
    )

    assert session.paths_pruned == 1
    assert seen_reasons == [DUPLICATE_STATE_PRUNE_REASON]


def test_record_duplicate_branch_state_ignores_non_branch_instruction() -> None:
    session = ExecutionSession()
    state = VMState(pc=1)

    pruned = record_duplicate_branch_state(
        session=session,
        state=state,
        instr=_instructions("x = 1")[0],
        hook_owner=object(),
        hooks={},
    )

    assert pruned is False
    assert session.visited_states == set()


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


def test_dispatch_instruction_records_snapshots_and_runs_post_step_hooks() -> None:
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
