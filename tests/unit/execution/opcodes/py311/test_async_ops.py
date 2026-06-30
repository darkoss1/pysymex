from __future__ import annotations

import dis

import pysymex._internal.execution.opcodes.py311.async_generators as async_ops
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def _instr(opname: str) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname)


def test_handle_async_gen_wrap() -> None:
    """Test handle_async_gen_wrap behavior."""
    state = VMState(stack=[10], pc=4)
    async_ops.handle_async_gen_wrap(_instr("ASYNC_GEN_WRAP"), state, OpcodeDispatcher())
