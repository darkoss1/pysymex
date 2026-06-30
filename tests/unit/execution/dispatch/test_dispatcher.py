from __future__ import annotations

import dis
from dataclasses import dataclass

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.result import OpcodeResult


def make_instruction(opname: str, offset: int = 0, argval: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, offset=offset, argval=argval)


@dataclass
class ExcEntry:
    start: int
    end: int
    target: int


def noop_handler(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    _ = instr
    _ = ctx
    return OpcodeResult.continue_with(state.advance_pc())


def test_register() -> None:
    dispatcher = OpcodeDispatcher()

    @dispatcher.register("A", "B")
    def local_handler(
        instr: dis.Instruction,
        state: VMState,
        ctx: OpcodeDispatcher,
    ) -> OpcodeResult:
        _ = instr
        _ = ctx
        return OpcodeResult.continue_with(state)

    assert dispatcher.has_handler("A") is True
    assert dispatcher.has_handler("B") is True
    assert callable(local_handler)


def test_register_handler() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.register_handler("LOAD_CONST", noop_handler)
    assert dispatcher.has_handler("LOAD_CONST") is True


def test_instructions() -> None:
    dispatcher = OpcodeDispatcher()
    instructions = [make_instruction("NOP", offset=0)]
    dispatcher.set_instructions(instructions)
    assert dispatcher.instructions == instructions


def test_dispatch_rejects_unknown_opcode_without_recovery_handler() -> None:
    dispatcher = OpcodeDispatcher()
    state = VMState()
    with pytest.raises(RuntimeError, match="Opcode not supported: UNKNOWN"):
        dispatcher.dispatch(make_instruction("UNKNOWN"), state)


def test_dispatch_cache_observes_late_instance_registration() -> None:
    dispatcher = OpcodeDispatcher()
    state = VMState()
    instr = make_instruction("LATE_LOCAL")

    with pytest.raises(RuntimeError, match="Opcode not supported: LATE_LOCAL"):
        dispatcher.dispatch(instr, state)

    dispatcher.register_handler("LATE_LOCAL", noop_handler)

    assert len(dispatcher.dispatch(instr, state).new_states) == 1


def test_dispatch_cache_observes_late_global_registration() -> None:
    dispatcher = OpcodeDispatcher()
    state = VMState()
    instr = make_instruction("LATE_GLOBAL")

    with pytest.raises(RuntimeError, match="Opcode not supported: LATE_GLOBAL"):
        dispatcher.dispatch(instr, state)

    OpcodeDispatcher.register_global("LATE_GLOBAL", noop_handler)

    assert len(dispatcher.dispatch(instr, state).new_states) == 1


def test_set_instructions() -> None:
    dispatcher = OpcodeDispatcher()
    instructions = [make_instruction("NOP", offset=8), make_instruction("NOP", offset=12)]
    dispatcher.set_instructions(instructions)
    assert dispatcher.instruction_count() == 2
    assert dispatcher.offset_to_index(12) == 1


def test_set_exception_entries() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_exception_entries([ExcEntry(start=0, end=10, target=20)])
    dispatcher.set_instructions([make_instruction("NOP", 0), make_instruction("NOP", 20)])
    assert dispatcher.find_exception_handler(5) == 1


def test_find_exception_handler() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_exception_entries([ExcEntry(start=3, end=5, target=99)])
    dispatcher.set_instructions([make_instruction("NOP", 99)])
    assert dispatcher.find_exception_handler(2) is None
    assert dispatcher.find_exception_handler(3) == 0


def test_find_exception_handler_prefers_innermost_range() -> None:
    dispatcher = OpcodeDispatcher()
    entries: list[object] = [
        ExcEntry(start=0, end=10, target=40),
        ExcEntry(start=3, end=6, target=60),
    ]
    dispatcher.set_exception_entries(entries)
    dispatcher.set_instructions([make_instruction("NOP", 40), make_instruction("NOP", 60)])
    assert dispatcher.find_exception_handler(4) == 1


def test_switching_to_unregistered_stream_clears_exception_entries() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([make_instruction("NOP", 20)])
    dispatcher.set_exception_entries([ExcEntry(start=0, end=10, target=20)])
    assert dispatcher.find_exception_handler(5) == 0

    dispatcher.set_instructions([make_instruction("NOP", 40)])

    assert dispatcher.find_exception_handler(5) is None


def test_get_instruction() -> None:
    dispatcher = OpcodeDispatcher()
    instructions = [make_instruction("NOP", 0)]
    dispatcher.set_instructions(instructions)
    assert dispatcher.get_instruction(0) == instructions[0]
    assert dispatcher.get_instruction(5) is None


def test_offset_to_index() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([make_instruction("NOP", 4)])
    assert dispatcher.offset_to_index(4) == 0
    assert dispatcher.offset_to_index(100) is None


def test_dispatch() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.register_handler("NOP", noop_handler)
    state = VMState()
    result = dispatcher.dispatch(make_instruction("NOP"), state)
    assert len(result.new_states) == 1


def test_has_handler() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.register_handler("X", noop_handler)
    assert dispatcher.has_handler("X") is True
    assert dispatcher.has_handler("Y") is False


def test_registered_opcodes() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.register_handler("ONE", noop_handler)
    opcodes = dispatcher.registered_opcodes()
    assert "ONE" in opcodes


def test_register_global() -> None:
    OpcodeDispatcher.register_global("GLOBAL_TEST", noop_handler)
    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("GLOBAL_TEST") is True


def test_instruction_count() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([make_instruction("NOP", 0), make_instruction("NOP", 2)])
    assert dispatcher.instruction_count() == 2


def test_opcode_handler() -> None:
    @opcode_handler("DECORATOR_REGISTERED")
    def decorated(
        instr: dis.Instruction,
        state: VMState,
        ctx: OpcodeDispatcher,
    ) -> OpcodeResult:
        _ = instr
        _ = ctx
        return OpcodeResult.continue_with(state)

    dispatcher = OpcodeDispatcher()
    assert dispatcher.has_handler("DECORATOR_REGISTERED") is True
    assert callable(decorated)
