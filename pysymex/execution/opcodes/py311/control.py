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

"""Control flow opcodes (jumps, branches, returns) for Python 3.11."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.execution.opcodes.common.control import (
    branch_feasible,
    get_truthy_expr,
    handle_common_for_iter,
    handle_common_get_iter,
    handle_common_get_len,
    handle_common_match_class,
    handle_common_match_keys,
    handle_common_match_mapping,
    handle_common_match_sequence,
    handle_common_raise_varargs,
    handle_common_return_value,
)

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("RESUME", "NOP")
def handle_no_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle no-op instructions."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("RETURN_VALUE")
def handle_return_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return handle_common_return_value(instr, state, ctx)


@opcode_handler("POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_FALSE")
def handle_pop_jump_if_false(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is false."""
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    true_feasible = branch_feasible(state.path_constraints, cond_expr)
    false_feasible = branch_feasible(state.path_constraints, not_cond_expr)

    branches: list[VMState] = []
    if true_feasible:
        true_state = state.fork()
        true_state = true_state.add_constraint(cond_expr)
        true_state = true_state.record_branch(cond_expr, True, state.pc)
        true_state = true_state.set_pc(state.pc + 1)
        branches.append(true_state)

    if false_feasible:
        false_state = state.fork()
        false_state = false_state.add_constraint(not_cond_expr)
        false_state = false_state.record_branch(cond_expr, False, state.pc)
        false_state = false_state.set_pc(target_index)
        branches.append(false_state)

    return OpcodeResult.branch(branches)


@opcode_handler("POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_BACKWARD_IF_TRUE")
def handle_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is true."""
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    true_feasible = branch_feasible(state.path_constraints, cond_expr)
    false_feasible = branch_feasible(state.path_constraints, not_cond_expr)

    branches: list[VMState] = []
    if true_feasible:
        true_state = state.fork()
        true_state = true_state.add_constraint(cond_expr)
        true_state = true_state.record_branch(cond_expr, True, state.pc)
        true_state = true_state.set_pc(target_index)
        branches.append(true_state)

    if false_feasible:
        false_state = state.fork()
        false_state = false_state.add_constraint(not_cond_expr)
        false_state = false_state.record_branch(cond_expr, False, state.pc)
        false_state = false_state.set_pc(state.pc + 1)
        branches.append(false_state)

    return OpcodeResult.branch(branches)


@opcode_handler("POP_JUMP_FORWARD_IF_NONE", "POP_JUMP_BACKWARD_IF_NONE")
def handle_pop_jump_if_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is None."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    is_none = isinstance(value, SymbolicNone)
    if is_none:
        state = state.set_pc(target_index)
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)

        none_feasible = branch_feasible(state.path_constraints, none_expr)
        not_none_feasible = branch_feasible(state.path_constraints, not_none_expr)

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
    else:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)


@opcode_handler("POP_JUMP_FORWARD_IF_NOT_NONE", "POP_JUMP_BACKWARD_IF_NOT_NONE")
def handle_pop_jump_if_not_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    value = state.pop()
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    is_none = isinstance(value, SymbolicNone)
    if is_none:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    elif isinstance(value, SymbolicValue):
        none_expr = value.is_none
        not_none_expr = z3.Not(none_expr)

        not_none_feasible = branch_feasible(state.path_constraints, not_none_expr)
        none_feasible = branch_feasible(state.path_constraints, none_expr)

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
    else:
        state = state.set_pc(target_index)
        return OpcodeResult.continue_with(state)


@opcode_handler("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT")
def handle_jump(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unconditional jump."""
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is not None:
        state = state.set_pc(target_index)
    else:
        state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP")
def handle_jump_or_pop(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if true/false, otherwise pop."""
    cond = state.peek()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1

    jump_on_true = instr.opname == "JUMP_IF_TRUE_OR_POP"
    jump_state = state.fork()
    jump_state = jump_state.add_constraint(cond_expr if jump_on_true else z3.Not(cond_expr))
    jump_state = jump_state.set_pc(target_index)
    pop_state = state.fork()
    pop_state = pop_state.add_constraint(z3.Not(cond_expr) if jump_on_true else cond_expr)
    pop_state.pop()
    pop_state = pop_state.set_pc(state.pc + 1)

    branches: list[VMState] = []
    if branch_feasible(state.path_constraints, cond_expr if jump_on_true else z3.Not(cond_expr)):
        branches.append(jump_state)
    if branch_feasible(state.path_constraints, z3.Not(cond_expr) if jump_on_true else cond_expr):
        branches.append(pop_state)
    if not branches:
        return OpcodeResult.terminate()
    return OpcodeResult.branch(branches)


@opcode_handler("RAISE_VARARGS")
def handle_raise_varargs(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Raise an exception, unwinding the block stack to find a handler."""
    return handle_common_raise_varargs(instr, state, ctx)


@opcode_handler("LOAD_ASSERTION_ERROR")
def handle_load_assertion_error(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load AssertionError for assert statements."""
    marker = SymbolicValue(
        _name="AssertionError",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    state = state.push(marker)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("FOR_ITER")
def handle_for_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
    return handle_common_for_iter(instr, state, ctx)


@opcode_handler("GET_ITER")
def handle_get_iter(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get iterator from iterable."""
    return handle_common_get_iter(instr, state, ctx)


@opcode_handler("GET_LEN")
def handle_get_len(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get length of top of stack."""
    return handle_common_get_len(instr, state, ctx)


@opcode_handler("MATCH_MAPPING")
def handle_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    return handle_common_match_mapping(instr, state, ctx)


@opcode_handler("MATCH_SEQUENCE")
def handle_match_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    return handle_common_match_sequence(instr, state, ctx)


@opcode_handler("MATCH_KEYS")
def handle_match_keys(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    return handle_common_match_keys(instr, state, ctx)


@opcode_handler("MATCH_CLASS")
def handle_match_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    return handle_common_match_class(instr, state, ctx)


@opcode_handler("PRINT_EXPR")
def handle_print_expr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle PRINT_EXPR."""
    _ = state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
