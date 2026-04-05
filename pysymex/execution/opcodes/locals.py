# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Local and global variable opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex._typing import StackValue, is_taintable
from pysymex.core.state import UNBOUND, is_bound
from pysymex.core.types import SymbolicNone, SymbolicString, SymbolicValue
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("LOAD_CONST")
def handle_load_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a constant onto the stack."""
    value = instr.argval
    if value is None:
        sym_val = SymbolicNone("load_const_None")
    elif isinstance(value, str):
        sym_val = SymbolicString.from_const(value)
    else:
        sym_val = SymbolicValue.from_const(value)

    state = state.push(sym_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST", "LOAD_FAST_CHECK")
def handle_load_fast(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load a local variable onto the stack."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val

    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST_LOAD_FAST")
def handle_load_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load two local variables onto the stack (Python 3.13+)."""
    _argval: object = instr.argval
    names: tuple[object, ...] = (
        cast("tuple[object, ...]", _argval) if isinstance(_argval, tuple) else (str(_argval),)
    )
    for name in names:
        name = str(name)
        raw_value = state.get_local(name)
        if is_bound(raw_value):
            value = raw_value
        else:
            sym_val, type_constraint = SymbolicValue.symbolic(name)
            state = state.set_local(name, sym_val)
            state = state.add_constraint(type_constraint)
            value = sym_val
        state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST")
def handle_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into local variable with implicit flow taint tracking."""
    name = str(instr.argval)
    value: StackValue = state.pop()
    if state.control_taint:
        if is_taintable(value):
            value = cast("StackValue", value.with_taint(state.control_taint))
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_STORE_FAST")
def handle_store_fast_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store two values into local variables (Python 3.13+) with implicit flow taint tracking."""
    _argval: object = instr.argval
    names: tuple[object, ...] = (
        cast("tuple[object, ...]", _argval) if isinstance(_argval, tuple) else (str(_argval),)
    )
    for name in names:
        name = str(name)
        value: StackValue = state.pop()
        if state.control_taint:
            if is_taintable(value):
                value = cast("StackValue", value.with_taint(state.control_taint))
        state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_FAST")
def handle_delete_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a local variable."""
    name = str(instr.argval)
    if name in state.local_vars:
        del state.local_vars[name]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_GLOBAL")
def handle_load_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a global variable onto the stack."""
    argval = instr.argval
    if isinstance(argval, tuple):
        argval_tuple: tuple[object, ...] = argval  # type: ignore[assignment]
        if len(argval_tuple) > 1:
            name = str(argval_tuple[1])
        elif argval_tuple:
            name = str(argval_tuple[0])
        else:
            name = ""
    else:
        name = str(argval)
    push_null = False
    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True
    value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"global_{name}")
        sym_val.model_name = name

        state = state.add_constraint(z3.Not(sym_val.is_none))

        state = state.set_global(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    if push_null:
        state = state.push(SymbolicNone())
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_GLOBAL")
def handle_store_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into a global variable."""
    name = str(instr.argval)
    value = state.pop()
    state = state.set_global(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_GLOBAL")
def handle_delete_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a global variable."""
    name = str(instr.argval)
    if name in state.global_vars:
        del state.global_vars[name]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_NAME")
def handle_load_name(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Load name from locals or globals."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value) and raw_value is not None:
        value = raw_value
    else:
        value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)

        import z3 as _z3

        state = state.add_constraint(_z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_NAME")
def handle_store_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store name in locals."""
    name = str(instr.argval)
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_NAME")
def handle_delete_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a name."""
    name = str(instr.argval)
    if name in state.local_vars:
        del state.local_vars[name]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_DEREF", "LOAD_CLOSURE")
def handle_load_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from closure/free variable."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value) and raw_value is not None:
        value = raw_value
    else:
        value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"closure_{name}")

        import z3 as _z3

        state = state.add_constraint(_z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_DEREF")
def handle_store_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store into closure variable."""
    name = str(instr.argval)
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MAKE_CELL", "COPY_FREE_VARS")
def handle_cell_ops(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Cell creation - mostly no-op for symbolic execution."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_delete_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete closure variable."""
    name = str(instr.argval)
    if name in state.local_vars:
        del state.local_vars[name]
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FAST_AND_CLEAR")
def handle_load_fast_and_clear(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load local variable and set slot to NULL (list comprehension save/restore)."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        value = SymbolicNone()
    state = state.push(value)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_LOAD_FAST")
def handle_store_fast_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store and immediately reload a local (Python 3.13+ optimization)."""
    _argval: object = instr.argval
    names: tuple[object, ...] = (
        cast("tuple[object, ...]", _argval)
        if isinstance(_argval, tuple)
        else (str(_argval), str(_argval))
    )
    store_name = str(names[0])
    load_name = str(names[1]) if len(names) > 1 else store_name
    value = state.pop()
    state = state.set_local(store_name, value)
    raw_loaded = state.get_local(load_name)
    if is_bound(raw_loaded):
        loaded = raw_loaded
    else:
        loaded, constraint = SymbolicValue.symbolic(load_name)
        state = state.add_constraint(constraint)
    state = state.push(loaded)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_FAST_MAYBE_NULL")
def handle_store_fast_maybe_null(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store to local that might be uninitialized (exception handling)."""
    name = str(instr.argval)
    value = state.pop() if state.stack else SymbolicNone()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_FROM_DICT_OR_DEREF")
def handle_load_from_dict_or_deref(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or closure (class body)."""
    name = str(instr.argval)
    if state.stack:
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


@opcode_handler("LOAD_FROM_DICT_OR_GLOBALS")
def handle_load_from_dict_or_globals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load from local namespace or globals (class body)."""
    name = str(instr.argval)
    if state.stack:
        state.pop()
    value = state.get_global(name)
    if value is None:
        value, constraint = SymbolicValue.symbolic(f"global_{name}")
        state = state.add_constraint(constraint)
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LOAD_LOCALS")
def handle_load_locals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push locals() dict onto stack."""
    locals_dict, constraint = SymbolicValue.symbolic(f"locals_{state.pc}")
    state = state.push(locals_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SETUP_ANNOTATIONS")
def handle_setup_annotations(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up __annotations__ dict (class/module level annotations)."""
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
