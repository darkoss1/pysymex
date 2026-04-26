from __future__ import annotations

import dis


from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py311 import stack


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
