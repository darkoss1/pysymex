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

"""Fused fast-local opcode handlers for Python 3.13+ bytecode.

Implements ``LOAD_FAST_LOAD_FAST``, ``STORE_FAST_STORE_FAST``, and related fused opcodes
that read or write two locals in one instruction. Decodes name tuples via
:mod:`pysymex.execution.opcodes.common.locals.helpers`; does not change closure semantics.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.state.types import is_bound
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.locals.helpers import decode_fast_name_tuple

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_load_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused load fast load fast (Python 3.13+)."""
    decoded = decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    for name in (name1, name2):
        raw_value = state.get_local(name)
        if is_bound(raw_value):
            value = raw_value
        else:
            sym_val, type_constraint = SymbolicValue.symbolic(f"load_fast_{name}@{state.pc}")
            state = state.set_local(name, sym_val)
            state = state.add_constraint(type_constraint)
            value = sym_val
        state = state.push(value)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_store_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused store fast load fast (Python 3.13+)."""
    decoded = decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    value1 = state.pop()
    state = state.set_local(name1, value1)

    raw_value2 = state.get_local(name2)
    if is_bound(raw_value2):
        value2 = raw_value2
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(f"load_fast_{name2}@{state.pc}")
        state = state.set_local(name2, sym_val)
        state = state.add_constraint(type_constraint)
        value2 = sym_val
    state = state.push(value2)

    return OpcodeResult.continue_with(state.advance_pc())


def handle_common_store_fast_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle fused store fast store fast (Python 3.13+)."""
    decoded = decode_fast_name_tuple(instr)
    if len(decoded) < 2:
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    name1, name2 = decoded[:2]
    value1 = state.pop()
    value2 = state.pop()
    state = state.set_local(name1, value1)
    state = state.set_local(name2, value2)
    return OpcodeResult.continue_with(state.advance_pc())
