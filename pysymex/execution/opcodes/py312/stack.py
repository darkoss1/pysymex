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

"""Stack manipulation opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.types.scalars import SymbolicNone
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("POP_TOP")
def handle_pop_top(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Discard top of stack."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("COPY")
def handle_copy(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Copy the i-th item to the top of stack (Python 3.11+)."""
    idx = int(instr.argval)
    if len(state.stack) >= idx:
        state = state.push(state.stack[-idx])
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SWAP")
def handle_swap(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Swap top of stack with i-th item (Python 3.11+)."""
    idx = int(instr.argval)
    if len(state.stack) >= idx and idx >= 1:
        state.stack[-1], state.stack[-idx] = state.stack[-idx], state.stack[-1]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("EXTENDED_ARG")
def handle_extended_arg(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extended argument prefix (handled by dis pre-calculating operands)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("PUSH_NULL")
def handle_push_null(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Push NULL onto stack (Python 3.11+ for CALL)."""
    null_val = SymbolicNone("PUSH_NULL_None")
    state = state.push(null_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CACHE")
def handle_cache(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Cache instruction - skip."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_instrumented(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented opcode pass-through (Python 3.13+ sys.monitoring).

    These opcodes wrap their base counterparts with monitoring hooks.
    In symbolic execution we simply advance past them since tracing
    metadata has no semantic effect on program behaviour.
    """
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
