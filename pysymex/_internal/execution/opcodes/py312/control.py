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

"""Control flow opcodes (jumps, branches, returns) for Python 3.12.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE, Z3_ZERO
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.feasibility.branches import (
    handle_common_jump,
    handle_common_pop_jump_bool,
    handle_common_pop_jump_if_none,
    handle_common_pop_jump_if_not_none,
)
from pysymex._internal.execution.opcodes.common.control.intrinsics import (
    handle_common_call_intrinsic_1,
    handle_control_call_intrinsic_2,
)
from pysymex._internal.execution.opcodes.common.control.iteration.handlers import (
    handle_common_end_for,
    handle_common_for_iter,
    handle_common_get_iter,
)
from pysymex._internal.execution.opcodes.common.control.length import handle_common_get_len
from pysymex._internal.execution.opcodes.common.control.match.handlers import (
    handle_common_match_class,
    handle_common_match_keys,
    handle_common_match_mapping,
    handle_common_match_sequence,
)
from pysymex._internal.execution.opcodes.common.control.raise_varargs import (
    handle_control_raise_varargs,
)
from pysymex._internal.execution.opcodes.common.control.returns.handlers import (
    handle_common_return_const,
    handle_common_return_value,
)
from pysymex._internal.execution.opcodes.common.metadata import (
    handle_common_metadata_noop,
    handle_common_reserved_opcode,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


@opcode_handler("RESUME", "NOP")
def handle_py312_no_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Advance past proven metadata no-op instructions."""
    return handle_common_metadata_noop(instr, state, ctx)


@opcode_handler("RETURN_VALUE")
def handle_py312_return_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return from function with inter-procedural support."""
    return handle_common_return_value(instr, state, ctx)


@opcode_handler("RETURN_CONST")
def handle_py312_return_const(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Return a constant (Python 3.12+) with inter-procedural support."""
    return handle_common_return_const(instr, state, ctx)


@opcode_handler("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE")
def handle_py312_pop_jump_if_true(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Conditional jump if top of stack is true/false."""
    return handle_common_pop_jump_bool(
        instr,
        state,
        ctx,
        jump_when_true=instr.opname == "POP_JUMP_IF_TRUE",
    )


@opcode_handler("POP_JUMP_IF_NONE")
def handle_py312_pop_jump_if_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Jump if top of stack is None."""
    return handle_common_pop_jump_if_none(instr, state, ctx)


@opcode_handler("POP_JUMP_IF_NOT_NONE")
def handle_py312_pop_jump_if_not_none(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Jump if top of stack is not None."""
    return handle_common_pop_jump_if_not_none(instr, state, ctx)


@opcode_handler("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT")
def handle_py312_jump(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Unconditional jump."""
    return handle_common_jump(instr, state, ctx)


@opcode_handler("RAISE_VARARGS")
def py312_raise_varargs_control(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Raise an exception, unwinding the block stack to find a handler."""
    return handle_control_raise_varargs(instr, state, ctx)


@opcode_handler("LOAD_ASSERTION_ERROR")
def handle_py312_load_assertion_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
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
def handle_py312_for_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Iterate over a sequence with symbolic index tracking."""
    return handle_common_for_iter(instr, state, ctx)


@opcode_handler("GET_ITER")
def handle_py312_get_iter(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get iterator from iterable."""
    return handle_common_get_iter(instr, state, ctx)


@opcode_handler("END_FOR")
def handle_py312_end_for(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """End of for loop cleanup."""
    return handle_common_end_for(instr, state, ctx)


@opcode_handler("GET_LEN")
def handle_py312_get_len(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Get length of top of stack."""
    return handle_common_get_len(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_1")
def handle_py312_call_intrinsic_1(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Call single-argument intrinsic function."""
    return handle_common_call_intrinsic_1(instr, state, ctx)


@opcode_handler("CALL_INTRINSIC_2")
def handle_py312_call_intrinsic_2(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Call two-argument intrinsic function."""
    return handle_control_call_intrinsic_2(instr, state, ctx)


@opcode_handler("MATCH_MAPPING")
def handle_py312_match_mapping(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Test whether the TOS match subject is a mapping.

    Delegates to :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
    return handle_common_match_mapping(instr, state, ctx)


@opcode_handler("MATCH_SEQUENCE")
def handle_py312_match_sequence(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Test whether the TOS match subject is a sequence.

    Delegates to :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes a
    truthy :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue` and leaves the
    subject on the stack.
    """
    return handle_common_match_sequence(instr, state, ctx)


@opcode_handler("MATCH_KEYS")
def handle_py312_match_keys(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Check if mapping has required keys for pattern matching."""
    return handle_common_match_keys(instr, state, ctx)


@opcode_handler("MATCH_CLASS")
def handle_py312_match_class(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Match a class pattern and push captured attribute values.

    Pops class, attribute-name tuple, and subject, then delegates to
    :mod:`pysymex._internal.execution.opcodes.common.control.match`. Pushes captured
    values on success or a no-match sentinel when the pattern cannot apply.

    Limitations:
        Symbolic subjects without a modeled ``isinstance`` path use conservative
        success expressions; custom classes may be approximated.
    """
    return handle_common_match_class(instr, state, ctx)


@opcode_handler("RESERVED")
def handle_py312_reserved(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Reject CPython reserved/internal opcode slots."""
    return handle_common_reserved_opcode(instr, state, ctx)


handle_no_op = handle_py312_no_op
handle_return_value = handle_py312_return_value
handle_return_const = handle_py312_return_const
handle_pop_jump_if_true = handle_py312_pop_jump_if_true
handle_pop_jump_if_none = handle_py312_pop_jump_if_none
handle_pop_jump_if_not_none = handle_py312_pop_jump_if_not_none
handle_jump = handle_py312_jump
handle_raise_varargs = py312_raise_varargs_control
handle_load_assertion_error = handle_py312_load_assertion_error
handle_for_iter = handle_py312_for_iter
handle_get_iter = handle_py312_get_iter
handle_end_for = handle_py312_end_for
handle_get_len = handle_py312_get_len
handle_call_intrinsic_1 = handle_py312_call_intrinsic_1
handle_call_intrinsic_2 = handle_py312_call_intrinsic_2
handle_match_mapping = handle_py312_match_mapping
handle_match_sequence = handle_py312_match_sequence
handle_match_keys = handle_py312_match_keys
handle_match_class = handle_py312_match_class
handle_reserved = handle_py312_reserved
