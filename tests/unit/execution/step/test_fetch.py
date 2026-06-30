"""Tests for one-step instruction fetching."""

from __future__ import annotations

import dis

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.step.fetch import fetch_instruction


def _instructions(source: str) -> list[dis.Instruction]:
    code = compile(source, "<step-test>", "exec")
    return list(dis.get_instructions(code))


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
