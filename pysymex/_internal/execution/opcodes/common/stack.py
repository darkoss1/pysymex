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

"""Stack manipulation opcode handlers (POP_TOP, COPY, SWAP, PUSH_NULL, caches).

Implements CPython 3.11+ stack depth helpers and no-fork opcodes that only adjust
``VMState.stack``. Version packages register thin wrappers; does not own calls or
locals (see :mod:`pysymex._internal.execution.opcodes.common.functions` and
:mod:`pysymex._internal.execution.opcodes.common.locals`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.metadata import (
    handle_common_instrumented_opcode,
    handle_common_metadata_noop,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    """Enforce minimum stack depth for opcode execution."""
    if len(state.stack) < required_depth:
        msg = (
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )
        raise VMStateError(
            msg,
        )


def handle_common_pop_top(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``POP_TOP``: remove one stack slot without pushing a result.

    CPython stack effect: ``--TOS``. Raises :class:`~pysymex._internal.core.state.types.VMStateError`
    when the stack is empty.
    """
    _require_stack_depth(state, instr, 1, "POP_TOP")
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_copy(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Copy the i-th item to the top of stack (Python 3.11+)."""
    idx = int(instr.argval)
    _require_stack_depth(state, instr, idx, f"COPY {idx}")
    state = state.push(state.stack[-idx])
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_swap(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Swap top of stack with i-th item (Python 3.11+)."""
    idx = int(instr.argval)
    _require_stack_depth(state, instr, idx, f"SWAP {idx}")
    state.stack[-1], state.stack[-idx] = state.stack[-idx], state.stack[-1]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_extended_arg(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Extended argument prefix (handled by dis pre-calculating operands)."""
    return handle_common_metadata_noop(instr, state, ctx)


def handle_common_push_null(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push NULL onto stack (Python 3.11+ for CALL)."""
    null_val = SymbolicNoneType("PUSH_NULL_None")
    state = state.push(null_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_cache(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Skip CPython adaptive interpreter cache metadata."""
    return handle_common_metadata_noop(instr, state, ctx)


def handle_common_instrumented(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject instrumented pseudo-opcodes until explicit lowering exists."""
    return handle_common_instrumented_opcode(instr, state, ctx)
