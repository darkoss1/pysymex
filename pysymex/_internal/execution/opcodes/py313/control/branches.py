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

"""Python 3.13 jump and truth-conversion opcode wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.truthiness import get_truthy_expr
from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branches import (
    handle_common_jump,
    handle_common_pop_jump_bool,
    handle_common_pop_jump_if_none,
    handle_common_pop_jump_if_not_none,
)
from pysymex._internal.execution.opcodes.common.control.truth.handlers import (
    resolve_heap_backed_truth_operand,
    try_dispatch_modeled_truth_protocol,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE")
def handle_py313_pop_jump_if_true(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Conditional jump if top of stack is true."""
    return handle_common_pop_jump_bool(
        instr,
        state,
        ctx,
        jump_when_true=instr.opname == "POP_JUMP_IF_TRUE",
    )


@opcode_handler("POP_JUMP_IF_NONE")
def handle_py313_pop_jump_if_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Jump if top of stack is None."""
    return handle_common_pop_jump_if_none(instr, state, ctx)


@opcode_handler("POP_JUMP_IF_NOT_NONE")
def handle_py313_pop_jump_if_not_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    return handle_common_pop_jump_if_not_none(instr, state, ctx)


@opcode_handler(
    "JUMP_FORWARD",
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "JUMP",
    "JUMP_NO_INTERRUPT",
)
def handle_py313_jump(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Unconditional jump."""
    return handle_common_jump(instr, state, ctx)


@opcode_handler("TO_BOOL")
def handle_to_bool(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Convert top of stack to bool (Python 3.12+)."""
    if state.stack:
        value = state.pop()
        truth_operand = resolve_heap_backed_truth_operand(value, state)
        modeled_result = try_dispatch_modeled_truth_protocol(truth_operand, state, ctx)
        if modeled_result is not None:
            return modeled_result
        truthy = get_truthy_expr(truth_operand)
        result = SymbolicValue(
            _name=f"to_bool_{state.pc}",
            z3_int=z3.If(truthy, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=truthy,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
        state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
