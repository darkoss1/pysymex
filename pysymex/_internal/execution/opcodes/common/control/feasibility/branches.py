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

"""Conditional branch and jump opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.truthiness import get_truthy_expr
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branching import (
    branch_feasible_pair,
    preferred_truth_order,
)
from pysymex._internal.execution.opcodes.common.control.truth.handlers import (
    resolve_heap_backed_truth_operand,
    try_dispatch_modeled_truth_protocol,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_pop_jump_bool(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    jump_when_true: bool,
) -> OpcodeResult:
    """Branch on stack truthiness and jump on the requested boolean outcome."""
    cond = state.pop()
    truth_operand = resolve_heap_backed_truth_operand(cond, state)
    modeled_result = try_dispatch_modeled_truth_protocol(
        truth_operand,
        state,
        ctx,
        resume_pc=state.pc,
    )
    if modeled_result is not None:
        return modeled_result

    cond_expr = get_truthy_expr(truth_operand)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    known_prefix_len = StateConstraints.known_sat_prefix_len(state)
    true_feasible, false_feasible = branch_feasible_pair(
        state.path_constraints,
        cond_expr,
        not_cond_expr,
        known_sat_prefix_len=known_prefix_len,
    )

    true_pc = target_index if jump_when_true else state.pc + 1
    false_pc = state.pc + 1 if jump_when_true else target_index
    fallthrough_first_order = (not jump_when_true, jump_when_true)

    branches: list[VMState] = []
    for truth_value in preferred_truth_order(
        state.path_constraints,
        cond_expr,
        not_cond_expr,
        default_order=fallthrough_first_order,
    ):
        if truth_value and true_feasible:
            true_state = state.fork()
            true_state = true_state.add_constraint(cond_expr)
            true_state = true_state.record_branch(cond_expr, True, state.pc)
            true_state = true_state.set_pc(true_pc)
            branches.append(true_state)
        elif not truth_value and false_feasible:
            false_state = state.fork()
            false_state = false_state.add_constraint(not_cond_expr)
            false_state = false_state.record_branch(cond_expr, False, state.pc)
            false_state = false_state.set_pc(false_pc)
            branches.append(false_state)

    return OpcodeResult.branch(branches)


def handle_common_pop_jump_if_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``POP_JUMP_IF_NONE``: pop and branch on ``None``."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    if isinstance(value, SymbolicNoneType):
        return OpcodeResult.continue_with(state.set_pc(target_index))

    if isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)
        known_prefix_len = StateConstraints.known_sat_prefix_len(state)
        none_feasible, not_none_feasible = branch_feasible_pair(
            state.path_constraints,
            none_expr,
            not_none_expr,
            known_sat_prefix_len=known_prefix_len,
        )

        branches: list[VMState] = []
        if none_feasible:
            none_state = state.fork()
            none_state = none_state.add_constraint(none_expr)
            none_state = none_state.record_branch(none_expr, True, state.pc)
            none_state = none_state.set_pc(target_index)
            branches.append(none_state)
        if not_none_feasible:
            not_none_state = state.fork()
            not_none_state = not_none_state.add_constraint(not_none_expr)
            not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
            not_none_state = not_none_state.set_pc(state.pc + 1)
            branches.append(not_none_state)
        return OpcodeResult.branch(branches)

    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_pop_jump_if_not_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``POP_JUMP_IF_NOT_NONE``: pop and branch on non-``None``."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    if isinstance(value, SymbolicNoneType):
        return OpcodeResult.continue_with(state.advance_pc())

    if isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)
        known_prefix_len = StateConstraints.known_sat_prefix_len(state)
        not_none_feasible, none_feasible = branch_feasible_pair(
            state.path_constraints,
            not_none_expr,
            none_expr,
            known_sat_prefix_len=known_prefix_len,
        )

        branches: list[VMState] = []
        if not_none_feasible:
            not_none_state = state.fork()
            not_none_state = not_none_state.add_constraint(not_none_expr)
            not_none_state = not_none_state.record_branch(none_expr, False, state.pc)
            not_none_state = not_none_state.set_pc(target_index)
            branches.append(not_none_state)
        if none_feasible:
            none_state = state.fork()
            none_state = none_state.add_constraint(none_expr)
            none_state = none_state.record_branch(none_expr, True, state.pc)
            none_state = none_state.set_pc(state.pc + 1)
            branches.append(none_state)
        return OpcodeResult.branch(branches)

    return OpcodeResult.continue_with(state.set_pc(target_index))


def handle_common_jump(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle an unconditional absolute target jump."""
    target_index = ctx.offset_to_index(int(instr.argval))
    state = state.set_pc(target_index) if target_index is not None else state.advance_pc()
    return OpcodeResult.continue_with(state)
