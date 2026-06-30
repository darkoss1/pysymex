# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Python 3.13 no-op, executor, and instrumented-marker handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.metadata import (
    handle_common_instrumented_opcode,
    handle_common_metadata_noop,
    handle_common_reserved_opcode,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("RESUME", "NOP")
def handle_py313_no_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Advance past proven metadata no-op instructions."""
    return handle_common_metadata_noop(instr, state, ctx)


@opcode_handler(
    "INSTRUMENTED_CALL",
    "INSTRUMENTED_CALL_FUNCTION_EX",
    "INSTRUMENTED_CALL_KW",
    "INSTRUMENTED_END_FOR",
    "INSTRUMENTED_END_SEND",
    "INSTRUMENTED_FOR_ITER",
    "INSTRUMENTED_INSTRUCTION",
    "INSTRUMENTED_JUMP_BACKWARD",
    "INSTRUMENTED_JUMP_FORWARD",
    "INSTRUMENTED_LINE",
    "INSTRUMENTED_LOAD_SUPER_ATTR",
    "INSTRUMENTED_POP_JUMP_IF_FALSE",
    "INSTRUMENTED_POP_JUMP_IF_NONE",
    "INSTRUMENTED_POP_JUMP_IF_NOT_NONE",
    "INSTRUMENTED_POP_JUMP_IF_TRUE",
    "INSTRUMENTED_RESUME",
    "INSTRUMENTED_RETURN_CONST",
    "INSTRUMENTED_RETURN_VALUE",
    "INSTRUMENTED_YIELD_VALUE",
)
def handle_instrumented(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject INSTRUMENTED_* pseudo-opcodes until explicit lowering exists."""
    return handle_common_instrumented_opcode(instr, state, ctx)


@opcode_handler("ENTER_EXECUTOR")
def handle_enter_executor(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject optimized-executor internal bytecode until explicit lowering exists."""
    return handle_common_reserved_opcode(instr, state, ctx)


@opcode_handler("EXIT_INIT_CHECK")
def handle_exit_init_check(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject import-init internal bytecode until explicit semantics exist."""
    return handle_common_reserved_opcode(instr, state, ctx)


@opcode_handler("RESERVED")
def handle_py313_reserved(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject CPython reserved/internal opcode slots."""
    return handle_common_reserved_opcode(instr, state, ctx)
