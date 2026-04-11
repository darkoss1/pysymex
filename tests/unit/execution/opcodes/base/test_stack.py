from __future__ import annotations

import dis

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.base import stack


def _instr(opname: str, argval: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)

def test_handle_pop_top() -> None:
    """Test handle_pop_top behavior."""
    state = VMState(stack=[1, 2], pc=10)
    result = stack.handle_pop_top(_instr("POP_TOP"), state, OpcodeDispatcher())
    assert state.stack == [1]
    assert result.new_states[0].pc == 11


def test_handle_dup_top() -> None:
    """Test handle_dup_top behavior."""
    state = VMState(stack=[5], pc=1)
    stack.handle_dup_top(_instr("DUP_TOP"), state, OpcodeDispatcher())
    assert state.stack == [5, 5]


def test_handle_dup_top_two() -> None:
    """Test handle_dup_top_two behavior."""
    state = VMState(stack=[1, 2], pc=1)
    stack.handle_dup_top_two(_instr("DUP_TOP_TWO"), state, OpcodeDispatcher())
    assert state.stack == [1, 2, 1, 2]


def test_handle_rot_two() -> None:
    """Test handle_rot_two behavior."""
    state = VMState(stack=[1, 2], pc=1)
    stack.handle_rot_two(_instr("ROT_TWO"), state, OpcodeDispatcher())
    assert state.stack == [2, 1]


def test_handle_rot_three() -> None:
    """Test handle_rot_three behavior."""
    state = VMState(stack=[1, 2, 3], pc=1)
    stack.handle_rot_three(_instr("ROT_THREE"), state, OpcodeDispatcher())
    assert state.stack == [3, 1, 2]


def test_handle_rot_four() -> None:
    """Test handle_rot_four behavior."""
    state = VMState(stack=[1, 2, 3, 4], pc=1)
    stack.handle_rot_four(_instr("ROT_FOUR"), state, OpcodeDispatcher())
    assert state.stack == [4, 1, 2, 3]


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
    """Test handle_instrumented behavior."""
    state = VMState(pc=15)
    stack.handle_instrumented(_instr("INSTRUMENTED_CALL"), state, OpcodeDispatcher())
    assert state.pc == 16
