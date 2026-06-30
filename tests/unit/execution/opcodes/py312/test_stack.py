from __future__ import annotations

import dis

import pytest

import pysymex._internal.execution.opcodes.py312.stack as stack
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def _instr(opname: str, argval: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_pop_top() -> None:
    """Test handle_pop_top behavior."""
    state = VMState(stack=[1, 2], pc=10)
    result = stack.handle_pop_top(_instr("POP_TOP"), state, OpcodeDispatcher())
    assert state.stack == [1]
    assert result.new_states[0].pc == 11


def test_handle_copy() -> None:
    """Test handle_copy behavior."""
    state = VMState(stack=[7, 8, 9], pc=1)
    stack.handle_copy(_instr("COPY", argval=2), state, OpcodeDispatcher())
    assert state.stack == [7, 8, 9, 8]


def test_handle_swap() -> None:
    """Test handle_swap behavior."""
    state = VMState(stack=[1, 2, 3], pc=1)
    stack.handle_swap(_instr("SWAP", argval=3), state, OpcodeDispatcher())
    assert state.stack == [3, 2, 1]


def test_handle_extended_arg() -> None:
    """Test handle_extended_arg behavior."""
    state = VMState(pc=4)
    stack.handle_extended_arg(_instr("EXTENDED_ARG"), state, OpcodeDispatcher())
    assert state.pc == 5


def test_handle_push_null() -> None:
    """Test handle_push_null behavior."""
    state = VMState(pc=9)
    stack.handle_push_null(_instr("PUSH_NULL"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicNone)
    assert state.pc == 10


def test_handle_cache() -> None:
    """Test handle_cache behavior."""
    state = VMState(pc=2)
    stack.handle_cache(_instr("CACHE"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_handle_instrumented() -> None:
    """Instrumented pseudo-opcodes must not be pass-through no-ops."""
    state = VMState(pc=15)
    with pytest.raises(RuntimeError, match="Unsupported instrumented pseudo-opcode"):
        stack.handle_instrumented(_instr("INSTRUMENTED_CALL"), state, OpcodeDispatcher())
    assert state.pc == 15
