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

"""Control flow opcodes (jumps, branches, returns) for Python 3.12."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast
from collections.abc import Callable

import z3

from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.core.types import SymbolicList
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


@opcode_handler("RETURN_CONST")
def handle_return_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Return a constant (Python 3.12+) with inter-procedural support."""
    const_val = instr.argval
    if const_val is None:
        return_value = SymbolicNone("return_None")
    else:
        return_value = SymbolicValue.from_const(const_val)

    issue = None
    if state.contract_frames:
        func = cast("Callable[..., object]", state.contract_frames.pop())
        config = getattr(ctx, "config", None)
        if config and getattr(config, "enable_contract_verification", False):
            from pysymex.contracts.injector import inject_postconditions

            issue = inject_postconditions(state, func, return_value, config)

    frame = state.pop_call()
    if frame is not None:
        state.local_vars = frame.local_vars
        state = state.set_pc(frame.return_pc)
        if frame.caller_instructions is not None:
            caller_instructions = cast("list[dis.Instruction]", frame.caller_instructions)
            state.current_instructions = cast("list[object]", caller_instructions)
            ctx.set_instructions(caller_instructions)
        state = state.push(return_value)
        state.depth -= 1
        if issue:
            return OpcodeResult.with_issue(state, issue)
        return OpcodeResult.continue_with(state)
    if issue:
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)
    return OpcodeResult.terminate()


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE")
def handle_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is true/false."""
    cond = state.pop()
    cond_expr = get_truthy_expr(cond)
    target_index = ctx.offset_to_index(int(instr.argval))
    if target_index is None:
        target_index = state.pc + 1
    not_cond_expr = z3.Not(cond_expr)

    true_feasible = branch_feasible(state.path_constraints, cond_expr)
    false_feasible = branch_feasible(state.path_constraints, not_cond_expr)

    if instr.opname == "POP_JUMP_IF_TRUE":
        true_target = target_index
        false_target = state.pc + 1
    else:
        true_target = state.pc + 1
        false_target = target_index

    branches: list[VMState] = []
    if true_feasible:
        true_state = state.fork()
        true_state = true_state.add_constraint(cond_expr)
        true_state = true_state.record_branch(cond_expr, True, state.pc)
        true_state = true_state.set_pc(true_target)
        branches.append(true_state)

    if false_feasible:
        false_state = state.fork()
        false_state = false_state.add_constraint(not_cond_expr)
        false_state = false_state.record_branch(cond_expr, False, state.pc)
        false_state = false_state.set_pc(false_target)
        branches.append(false_state)

    return OpcodeResult.branch(branches)


@opcode_handler("POP_JUMP_IF_NONE")
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


@opcode_handler("POP_JUMP_IF_NOT_NONE")
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


@opcode_handler("END_FOR")
def handle_end_for(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """End of for loop cleanup."""
    if state.stack:
        state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("GET_LEN")
def handle_get_len(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Get length of top of stack."""
    return handle_common_get_len(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_1")
def handle_call_intrinsic_1(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call single-argument intrinsic function."""
    arg = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        state = state.push(SymbolicNone())
    elif intrinsic_id == 2:
        state = state.push(SymbolicNone())
    elif intrinsic_id == 3:
        exc_val, constraint = SymbolicValue.symbolic(f"runtime_error_{state.pc}")
        state = state.push(exc_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 4:
        wrapped, constraint = SymbolicValue.symbolic(f"async_gen_wrap_{state.pc}")
        state = state.push(wrapped)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 5:
        if arg is not None:
            state = state.push(arg)
        else:
            val, constraint = SymbolicValue.symbolic(f"upos_{state.pc}")
            state = state.push(val)
            state = state.add_constraint(constraint)
    elif intrinsic_id == 6:
        if isinstance(arg, SymbolicList):
            state = state.push(arg)
        else:
            result, constraint = SymbolicValue.symbolic(f"tuple_{state.pc}")
            state = state.push(result)
            state = state.add_constraint(constraint)
    elif intrinsic_id in (7, 8, 9):
        _type_names = {7: "TypeVar", 8: "ParamSpec", 9: "TypeVarTuple"}
        type_val, constraint = SymbolicValue.symbolic(f"{_type_names[intrinsic_id]}_{state.pc}")
        state = state.push(type_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 10:
        result, constraint = SymbolicValue.symbolic(f"generic_alias_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 11:
        alias_val, constraint = SymbolicValue.symbolic(f"type_alias_{state.pc}")
        state = state.push(alias_val)
        state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic1_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_INTRINSIC_2")
def handle_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call two-argument intrinsic function."""
    _arg2 = state.pop() if state.stack else None
    arg1 = state.pop() if state.stack else None
    intrinsic_id = int(instr.argval) if instr.argval else 0

    if intrinsic_id == 1:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            exc_val, constraint = SymbolicValue.symbolic(f"reraise_{state.pc}")
            state = state.push(exc_val)
            state = state.add_constraint(constraint)
    elif intrinsic_id in (2, 3):
        _names = {2: "TypeVar_bound", 3: "TypeVar_constrained"}
        tv_val, constraint = SymbolicValue.symbolic(f"{_names[intrinsic_id]}_{state.pc}")
        state = state.push(tv_val)
        state = state.add_constraint(constraint)
    elif intrinsic_id == 4:
        if arg1 is not None:
            state = state.push(arg1)
        else:
            func_val, constraint = SymbolicValue.symbolic(f"typed_func_{state.pc}")
            state = state.push(func_val)
            state = state.add_constraint(constraint)
    else:
        result, constraint = SymbolicValue.symbolic(f"intrinsic2_{state.pc}")
        state = state.push(result)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


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


@opcode_handler("NOP", "RESERVED")
def handle_nop_and_reserved(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle NOP and RESERVED (No-op)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
