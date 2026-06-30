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

"""Stack manipulation opcode wrappers for Python 3.13.

Registers stack primitives and PEP 669 ``INSTRUMENTED_*`` rejection handlers
via :mod:`pysymex._internal.execution.opcodes.common.stack`. Does not manage frame locals,
the block stack, or sys.monitoring event delivery.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.stack import (
    handle_common_cache,
    handle_common_copy,
    handle_common_extended_arg,
    handle_common_instrumented,
    handle_common_pop_top,
    handle_common_push_null,
    handle_common_swap,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("POP_TOP")
def handle_py313_pop_top(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Discard top of stack."""
    return handle_common_pop_top(instr, state, ctx)


@opcode_handler("COPY")
def handle_py313_copy(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Copy the i-th item to the top of stack (Python 3.11+)."""
    return handle_common_copy(instr, state, ctx)


@opcode_handler("SWAP")
def handle_py313_swap(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Swap top of stack with i-th item (Python 3.11+)."""
    return handle_common_swap(instr, state, ctx)


@opcode_handler("EXTENDED_ARG")
def handle_py313_extended_arg(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Extended argument prefix (handled by dis pre-calculating operands)."""
    return handle_common_extended_arg(instr, state, ctx)


@opcode_handler("PUSH_NULL")
def handle_py313_push_null(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push NULL onto stack (Python 3.11+ for CALL)."""
    return handle_common_push_null(instr, state, ctx)


@opcode_handler("CACHE")
def handle_py313_cache(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Cache instruction - skip."""
    return handle_common_cache(instr, state, ctx)


@opcode_handler(
    "INSTRUMENTED_RESUME",
    "INSTRUMENTED_END_FOR",
    "INSTRUMENTED_END_SEND",
    "INSTRUMENTED_RETURN_VALUE",
    "INSTRUMENTED_RETURN_CONST",
    "INSTRUMENTED_YIELD_VALUE",
    "INSTRUMENTED_LOAD_SUPER_ATTR",
    "INSTRUMENTED_FOR_ITER",
    "INSTRUMENTED_CALL",
    "INSTRUMENTED_CALL_KW",
    "INSTRUMENTED_CALL_FUNCTION_EX",
    "INSTRUMENTED_INSTRUCTION",
    "INSTRUMENTED_JUMP_FORWARD",
    "INSTRUMENTED_JUMP_BACKWARD",
    "INSTRUMENTED_POP_JUMP_IF_TRUE",
    "INSTRUMENTED_POP_JUMP_IF_FALSE",
    "INSTRUMENTED_POP_JUMP_IF_NONE",
    "INSTRUMENTED_POP_JUMP_IF_NOT_NONE",
    "INSTRUMENTED_LINE",
)
def handle_py313_instrumented(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Unsupported instrumented pseudo-opcode (Python 3.13+ sys.monitoring)."""
    return handle_common_instrumented(instr, state, ctx)


handle_pop_top = handle_py313_pop_top
handle_copy = handle_py313_copy
handle_swap = handle_py313_swap
handle_extended_arg = handle_py313_extended_arg
handle_push_null = handle_py313_push_null
handle_cache = handle_py313_cache
handle_instrumented = handle_py313_instrumented
