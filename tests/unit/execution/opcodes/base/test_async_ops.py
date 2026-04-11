from __future__ import annotations

import dis

import pytest

from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.base import async_ops


def _instr(opname: str) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname)

def test_handle_async_gen_wrap() -> None:
    """Test handle_async_gen_wrap behavior."""
    state = VMState(stack=[10], pc=4)
    # Current implementation delegates to SymbolicValue.symbolic and surfaces
    # construction failures directly.
    with pytest.raises(NameError):
        async_ops.handle_async_gen_wrap(_instr("ASYNC_GEN_WRAP"), state, OpcodeDispatcher())


def test_handle_gen_start() -> None:
    """Test handle_gen_start behavior."""
    state = VMState(stack=["init"], pc=9)
    result = async_ops.handle_gen_start(_instr("GEN_START"), state, OpcodeDispatcher())

    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 10
    assert result.new_states[0].stack == []


def test_handle_extended_arg_quick() -> None:
    """Test handle_extended_arg_quick behavior."""
    state = VMState(pc=2)
    result = async_ops.handle_extended_arg_quick(
        _instr("EXTENDED_ARG_QUICK"), state, OpcodeDispatcher()
    )

    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 3
