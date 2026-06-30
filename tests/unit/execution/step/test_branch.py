"""Tests for one-step branch duplicate pruning."""

from __future__ import annotations

import dis

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import CallFrame, wrap_cow_dict
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.execution.step.branch import (
    DUPLICATE_STATE_PRUNE_REASON,
    build_state_key,
    is_branch_or_jump_instruction,
    record_duplicate_branch_state,
)


def _instructions(source: str) -> list[dis.Instruction]:
    code = compile(source, "<step-test>", "exec")
    return list(dis.get_instructions(code))


def _branch_instruction() -> dis.Instruction:
    return next(
        instr for instr in _instructions("if flag:\n    value = 1") if "JUMP" in instr.opname
    )


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
