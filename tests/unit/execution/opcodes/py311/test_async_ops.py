from __future__ import annotations

import dis

from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py311 import async_ops


def _instr(opname: str) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname)


def test_handle_async_gen_wrap() -> None:
    """Test handle_async_gen_wrap behavior."""
    state = VMState(stack=[10], pc=4)
    async_ops.handle_async_gen_wrap(_instr("ASYNC_GEN_WRAP"), state, OpcodeDispatcher())
