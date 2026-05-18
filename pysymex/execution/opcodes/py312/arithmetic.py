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

"""Arithmetic opcode wrappers for Python 3.12."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, TypeGuard

from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler
from pysymex.execution.opcodes.common.numeric import (
    check_division_by_zero as _check_division_by_zero,
    check_negative_shift as _check_negative_shift,
    handle_numeric_binary_op,
    handle_unary_invert as handle_common_unary_invert,
)

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


def _is_concrete_numeric(value: object) -> TypeGuard[int | float | bool]:
    """Return whether *value* supports Python unary numeric operators."""
    return isinstance(value, (int, float, bool))


def check_division_by_zero(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Compatibility wrapper for the shared division-by-zero predicate."""
    return _check_division_by_zero(right, state, op, left)


def check_negative_shift(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Compatibility wrapper for the shared negative-shift predicate."""
    return _check_negative_shift(right, state, op, left)


@opcode_handler("BINARY_OP")
def handle_binary_op(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Dispatch numeric ``BINARY_OP`` handling through shared Phase 1 semantics."""
    return handle_numeric_binary_op(instr, state, ctx)


@opcode_handler("UNARY_POSITIVE")
def handle_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``+`` semantics.

    CPython raises ``TypeError`` for ``+`` on non-numeric types (e.g. ``str``).
    Symbolic strings therefore terminate this path rather than pass through silently.
    """
    _ = (instr, ctx)
    value = state.pop()
    if _is_concrete_numeric(value):
        state = state.push(+value)  # type: ignore[operator]  # TypeGuard narrows to int|float|bool
        return OpcodeResult.continue_with(state.advance_pc())
    if isinstance(value, SymbolicString):
        # CPython: TypeError: bad operand type for unary +: 'str'
        return OpcodeResult.terminate()
    symbolic = SymbolicValue.from_const(value)
    state = state.push(symbolic)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("UNARY_NEGATIVE")
def handle_unary_negative(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``-`` semantics."""
    _ = (instr, ctx)
    value = state.pop()
    if _is_concrete_numeric(value):
        state = state.push(-value)
    else:
        symbolic = SymbolicValue.from_const(value)
        state = state.push(-symbolic)
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("UNARY_NOT")
def handle_unary_not(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Apply Python unary ``not`` semantics."""
    _ = (instr, ctx)
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    state = state.push(symbolic.logical_not())
    return OpcodeResult.continue_with(state.advance_pc())


@opcode_handler("UNARY_INVERT")
def handle_unary_invert(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Apply Python unary ``~`` semantics."""
    _ = (instr, ctx)
    return handle_common_unary_invert(state)


@opcode_handler("LOAD_ATTR")
def handle_load_attr(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load an attribute, checking heap memory and enhanced object state."""
    from pysymex.execution.opcodes.common.functions import handle_common_load_method

    return handle_common_load_method(instr, state, ctx)
