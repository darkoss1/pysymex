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

"""Common stack manipulation operations for opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.state import VMStateError
from pysymex.core.types import SymbolicNone
from pysymex.execution.dispatcher import OpcodeResult

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def handle_common_pop_top(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Discard top of stack."""
    _require_stack_depth(state, instr, 1, "POP_TOP")
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_copy(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Copy the i-th item to the top of stack (Python 3.11+)."""
    idx = int(instr.argval)
    _require_stack_depth(state, instr, idx, f"COPY {idx}")
    state = state.push(state.stack[-idx])
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_swap(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Swap top of stack with i-th item (Python 3.11+)."""
    idx = int(instr.argval)
    _require_stack_depth(state, instr, idx, f"SWAP {idx}")
    state.stack[-1], state.stack[-idx] = state.stack[-idx], state.stack[-1]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_extended_arg(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extended argument prefix (handled by dis pre-calculating operands)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_push_null(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push NULL onto stack (Python 3.11+ for CALL)."""
    null_val = SymbolicNone("PUSH_NULL_None")
    state = state.push(null_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_cache(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Cache instruction - skip."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_instrumented(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Instrumented opcode pass-through (Python 3.13+ sys.monitoring)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
