# pysymex: Python Symbolic Execution & Formal Verification
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

"""Instrumentation opcodes (PEP 669) for Python 3.12+.

These opcodes are used for monitoring, profiling, and debugging tools.
For symbolic execution, they are treated as no-ops since they don't
affect program semantics - they only insert instrumentation events.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("INSTRUMENTED_CALL")
def handle_instrumented_call(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented call (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_CALL_FUNCTION_EX")
def handle_instrumented_call_function_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented CALL_FUNCTION_EX (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_END_FOR")
def handle_instrumented_end_for(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented end of for loop (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_END_SEND")
def handle_instrumented_end_send(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented end of send (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_FOR_ITER")
def handle_instrumented_for_iter(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented for iteration (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_INSTRUCTION")
def handle_instrumented_instruction(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented instruction marker (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_JUMP_BACKWARD")
def handle_instrumented_jump_backward(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented backward jump (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_JUMP_FORWARD")
def handle_instrumented_jump_forward(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented forward jump (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_LINE")
def handle_instrumented_line(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented line marker (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_LOAD_SUPER_ATTR")
def handle_instrumented_load_super_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented super attribute load (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_POP_JUMP_IF_FALSE")
def handle_instrumented_pop_jump_if_false(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented conditional jump if false (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_POP_JUMP_IF_NONE")
def handle_instrumented_pop_jump_if_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented jump if None (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_POP_JUMP_IF_NOT_NONE")
def handle_instrumented_pop_jump_if_not_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented jump if not None (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_POP_JUMP_IF_TRUE")
def handle_instrumented_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented conditional jump if true (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_RESUME")
def handle_instrumented_resume(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented resume (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_RETURN_CONST")
def handle_instrumented_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented return constant (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_RETURN_VALUE")
def handle_instrumented_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented return value (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("INSTRUMENTED_YIELD_VALUE")
def handle_instrumented_yield_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented yield value (PEP 669)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
