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

"""Control flow opcodes (jumps, branches, returns) for Python 3.13.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_ONE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.control.feasibility import (
    get_truthy_expr,
    handle_common_jump,
    handle_common_pop_jump_bool,
    handle_common_pop_jump_if_none,
    handle_common_pop_jump_if_not_none,
    resolve_heap_backed_truth_operand,
    try_dispatch_modeled_truth_protocol,
)
from pysymex.execution.opcodes.common.control.flow import (
    handle_common_call_intrinsic_1,
    handle_common_call_intrinsic_2,
    handle_common_for_iter,
    handle_common_get_iter,
    handle_common_get_len,
    handle_common_raise_varargs,
)
from pysymex.execution.opcodes.common.control.match import (
    handle_common_match_class,
    handle_common_match_keys,
    handle_common_match_mapping,
    handle_common_match_sequence,
)
from pysymex.execution.opcodes.common.control.returns import (
    handle_common_return_const,
    handle_common_return_value,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


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
    """Return a constant (Python 3.13+) with inter-procedural support."""
    return handle_common_return_const(instr, state, ctx)


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE")
def handle_pop_jump_if_true(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Conditional jump if top of stack is true."""
    return handle_common_pop_jump_bool(
        instr,
        state,
        ctx,
        jump_when_true=instr.opname == "POP_JUMP_IF_TRUE",
    )


@opcode_handler("POP_JUMP_IF_NONE")
def handle_pop_jump_if_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is None."""
    return handle_common_pop_jump_if_none(instr, state, ctx)


@opcode_handler("POP_JUMP_IF_NOT_NONE")
def handle_pop_jump_if_not_none(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    return handle_common_pop_jump_if_not_none(instr, state, ctx)


@opcode_handler(
    "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP", "JUMP_NO_INTERRUPT"
)
def handle_jump(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unconditional jump."""
    return handle_common_jump(instr, state, ctx)


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
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
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
    next_instr = ctx.get_instruction(state.pc + 1)
    next_is_cleanup_pop = next_instr is not None and next_instr.opname == "POP_TOP"
    if state.stack and (isinstance(state.stack[-1], SymbolicNone) or not next_is_cleanup_pop):
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
    return handle_common_call_intrinsic_1(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_2")
def handle_call_intrinsic_2(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Call two-argument intrinsic function."""
    return handle_common_call_intrinsic_2(instr, state, ctx)


@opcode_handler("MATCH_MAPPING")
def handle_match_mapping(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Test whether the TOS match subject is a mapping.

    Delegates to :mod:`pysymex.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
    return handle_common_match_mapping(instr, state, ctx)


@opcode_handler("MATCH_SEQUENCE")
def handle_match_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Test whether the TOS match subject is a sequence.

    Delegates to :mod:`pysymex.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
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
    """Match a class pattern and push captured attribute values.

    Pops class, attribute-name tuple, and subject, then delegates to
    :mod:`pysymex.execution.opcodes.common.control.match`. Pushes captured
    values on success or a no-match sentinel when the pattern cannot apply.

    Limitations:
        Symbolic subjects without a modeled ``isinstance`` path use conservative
        success expressions; custom classes may be approximated.
    """
    return handle_common_match_class(instr, state, ctx)


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
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Catch-all for INSTRUMENTED_* pseudo-opcodes."""
    raise ValueError(f"Pseudo-opcode {instr.opname} should not be in user bytecode.")


@opcode_handler("ENTER_EXECUTOR")
def handle_enter_executor(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Advance past ``ENTER_EXECUTOR`` (executor entry marker).

    CPython 3.13+ emits this at optimized executor boundaries. PySyMex advances
    the program counter without modeling subinterpreter or executor isolation.

    Limitations:
        Executor/subinterpreter semantics are not modeled; exploration treats
        this opcode as a no-op for continuity.
    """
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("EXIT_INIT_CHECK")
def handle_exit_init_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Advance past ``EXIT_INIT_CHECK`` (package init guard).

    CPython emits this after submodule import initialization checks. PySyMex
    advances the program counter without enforcing import-time init invariants.

    Limitations:
        Import initialization order and side effects are not verified
        symbolically.
    """
    return OpcodeResult.continue_with(state.advance_pc())


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


@opcode_handler("NOP", "RESERVED")
def handle_nop_and_reserved(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle NOP and RESERVED (No-op)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
