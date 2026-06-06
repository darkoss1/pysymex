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

"""Closure and cell opcodes (LOAD/STORE/DELETE_DEREF, COPY_FREE_VARS, LOAD_CLOSURE).

Materializes cell contents from ``VMState`` closure tables and copies free variables
into nested frames. Class/namespace variants delegate to dict or globals when the
operand names a non-cell binding.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import closure_write_location
from pysymex.core.identity.addressing import next_address
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.state.types import UNBOUND, is_bound
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.locals.helpers import require_stack_depth

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_load_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from closure/free variable."""
    name = str(instr.argval)
    cell = state.get_local(name)

    if not (isinstance(cell, SymbolicObject) and cell.name.startswith("cell_")):
        addr = next_address()
        if not is_bound(cell) or cell is None:
            sym_val, constraint = SymbolicValue.symbolic(f"deref_{name}")
            state = state.add_constraint(constraint)
            state = state.store_heap(addr, sym_val)
        else:
            state = state.store_heap(addr, cell)
        cell = SymbolicObject(f"cell_{name}", addr, get_int_val(addr), {addr})
        state = state.set_local(name, cell)

    value = state.memory.get(cell.address)
    if value is None:
        value = SymbolicNone()

    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store into closure variable."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "STORE_DEREF value")
    value = state.pop()

    cell = state.get_local(name)

    if isinstance(cell, SymbolicObject) and cell.name.startswith("cell_"):
        state = state.store_heap(cell.address, value)
    else:
        addr = next_address()
        state = state.store_heap(addr, value)
        cell = SymbolicObject(f"cell_{name}", addr, get_int_val(addr), {addr})
        state = state.set_local(name, cell)

    location = closure_write_location(name)
    state = state.record_write_event(
        WriteEvent(WriteKind.CLOSURE, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_cell_ops(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Cell creation - mostly no-op for symbolic execution."""
    if instr.opname == "MAKE_CELL":
        name = str(instr.argval)
        val = state.get_local(name)
        if val is None:
            val = SymbolicNone()

        addr = next_address()
        state = state.store_heap(addr, SymbolicValue.from_const(val))
        cell_obj = SymbolicObject(f"cell_{name}", addr, get_int_val(addr), {addr})
        state = state.set_local(name, cell_obj)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``DELETE_DEREF``: clear a closure cell referenced by ``instr.argval``.

    CPython stack effect: none. Removes the cell binding when tracked in the frame.
    """
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    location = closure_write_location(name)
    state = state.record_write_event(
        WriteEvent(WriteKind.CLOSURE, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_from_dict_or_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or closure (class body)."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "LOAD_FROM_DICT_OR_DEREF namespace")
    state.pop()
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        value, constraint = SymbolicValue.symbolic(f"deref_{name}")
        state = state.add_constraint(constraint)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_from_dict_or_globals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or globals (class body)."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "LOAD_FROM_DICT_OR_GLOBALS namespace")
    state.pop()
    value = state.get_global(name)
    if value is None:
        value, constraint = SymbolicValue.symbolic(f"global_{name}")
        state = state.add_constraint(constraint)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_copy_free_vars(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Copy free variables from closure to cell variables."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_closure(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``LOAD_CLOSURE`` / ``LOAD_CLASSDEREF``: push a cell object for ``argval``.

    Used before ``MAKE_FUNCTION`` to capture free variables; pushes a symbolic cell
    when the closure slot is not yet materialized.
    """
    name = str(instr.argval)
    val = state.get_local(name)

    if not (isinstance(val, SymbolicObject) and val.name.startswith("cell_")):
        addr = next_address()
        if is_bound(val) and val is not None:
            state = state.store_heap(addr, val)
        else:
            sym_val, constraint = SymbolicValue.symbolic(f"closure_{name}_{state.pc}")
            state = state.add_constraint(constraint)
            state = state.store_heap(addr, sym_val)
        val = SymbolicObject(f"cell_{name}", addr, get_int_val(addr), {addr})
        state = state.set_local(name, val)
    state = state.push(val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
