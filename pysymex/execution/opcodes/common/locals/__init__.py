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

"""LOAD_*, STORE_*, and DELETE_* handlers for fast locals, names, and globals.

Reads and writes ``VMState.locals``, closure cells (via
:mod:`pysymex.execution.opcodes.common.locals.closure`), and module globals with
symbolic fallbacks when bindings are unknown. Fused fast-local opcodes live in
:mod:`pysymex.execution.opcodes.common.locals.fused` (Python 3.13+).
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.bytecode import global_name_from_argval
from pysymex.core.constants import Z3_TRUE
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import global_write_location
from pysymex.core.state.types import UNBOUND, is_bound
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.locals.closure import (
    handle_common_cell_ops as handle_common_cell_ops,
    handle_common_copy_free_vars as handle_common_copy_free_vars,
    handle_common_delete_deref as handle_common_delete_deref,
    handle_common_load_closure as handle_common_load_closure,
    handle_common_load_deref as handle_common_load_deref,
    handle_common_load_from_dict_or_deref as handle_common_load_from_dict_or_deref,
    handle_common_load_from_dict_or_globals as handle_common_load_from_dict_or_globals,
    handle_common_store_deref as handle_common_store_deref,
)
from pysymex.execution.opcodes.common.locals.fused import (
    handle_common_load_fast_load_fast as handle_common_load_fast_load_fast,
    handle_common_store_fast_load_fast as handle_common_store_fast_load_fast,
    handle_common_store_fast_store_fast as handle_common_store_fast_store_fast,
)
from pysymex.execution.opcodes.common.locals.helpers import require_stack_depth
from pysymex.typing import StackValue

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_load_const(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a constant onto the stack."""
    value = instr.argval
    sym_val: StackValue
    if value is None:
        sym_val = SymbolicNone("load_const_None")
    elif isinstance(value, str):
        sym_val = SymbolicString.from_const(value)
    elif isinstance(value, tuple):
        # Immutable literal tuples carry sequence and pattern metadata exactly.
        sym_val = cast("StackValue", value)
    else:
        sym_val = SymbolicValue.from_const(value)

    state = state.push(sym_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a local variable onto the stack."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if any(
            s in name.lower()
            for s in ("substitutions", "config", "mapping", "settings", "options_map")
        ):
            sym_val.is_dict = Z3_TRUE

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val

    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_check(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load local variable with UnboundLocalError check."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value):
        value = raw_value
    else:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if any(
            s in name.lower()
            for s in ("substitutions", "config", "mapping", "settings", "options_map")
        ):
            sym_val.is_dict = Z3_TRUE

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into local variable."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "STORE_FAST value")
    value: StackValue = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_fast(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``DELETE_FAST``: remove a fast-local binding when present.

    CPython stack effect: none (operand names the slot). No-op when the slot is unset.
    """
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load a global variable onto the stack."""
    from pysymex.execution.opcodes.common import BUILTIN_TYPES

    name = global_name_from_argval(instr.argval)
    push_null = False
    if hasattr(instr, "arg") and instr.arg is not None:
        if instr.arg & 1:
            push_null = True
    value = state.get_global(name)

    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(f"global_{name}")
        if name.isupper() and any(
            s in name for s in ("_SUBSTITUTIONS", "_MAP", "_DICT", "_MAPPING")
        ):
            sym_val.is_dict = Z3_TRUE

        sym_val.model_name = name
        if name in BUILTIN_TYPES:
            sym_val.affinity_type = BUILTIN_TYPES[name]
        state = state.add_constraint(z3.Not(sym_val.is_none))

        state = state.set_global(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    if push_null:
        state = state.push(SymbolicNone())
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store top of stack into a global variable."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "STORE_GLOBAL value")
    value = state.pop()
    state = state.set_global(name, value)
    location = global_write_location(name)
    state = state.record_write_event(
        WriteEvent(WriteKind.GLOBAL, location.name, state.pc, location.precise, instr.opname)
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_global(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete a global variable."""
    name = str(instr.argval)
    if name in state.global_vars:
        del state.global_vars[name]
        location = global_write_location(name)
        state = state.record_write_event(
            WriteEvent(WriteKind.GLOBAL, location.name, state.pc, location.precise, instr.opname)
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load name from locals or globals."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    if is_bound(raw_value) and raw_value is not None:
        value = raw_value
    else:
        value = state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        if name.isupper() and any(
            s in name for s in ("_SUBSTITUTIONS", "_MAP", "_DICT", "_MAPPING")
        ):
            state = state.add_constraint(sym_val.is_dict)

        import z3

        state = state.add_constraint(z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``STORE_NAME``: pop TOS into ``locals`` under ``instr.argval``.

    Creates or overwrites the named local. At root ``exec``/module scope, CPython
    uses one namespace for locals and globals, so root writes are also visible to
    nested functions that resolve the name through ``LOAD_GLOBAL``.
    """
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "STORE_NAME value")
    value = state.pop()
    state = state.set_local(name, value)
    if not state.call_stack:
        state = state.set_global(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``DELETE_NAME``: remove a ``locals`` entry by name.

    Mirrors ``DELETE_FAST`` for non-fast scopes; silently continues when absent.
    """
    name = str(instr.argval)
    state = state.set_local(name, UNBOUND)
    if not state.call_stack and name in state.global_vars:
        del state.global_vars[name]
        state.invalidate_cached_hash()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_fast_and_clear(
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


def handle_common_store_fast_maybe_null(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store to local that might be uninitialized (exception handling)."""
    name = str(instr.argval)
    require_stack_depth(state, instr, 1, "STORE_FAST_MAYBE_NULL value")
    value = state.pop()
    state = state.set_local(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_load_locals(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push locals() dict onto stack."""
    locals_dict, constraint = SymbolicValue.symbolic(f"locals_{state.pc}")
    state = state.push(locals_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_annotations(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set up __annotations__ dict (class/module level annotations)."""
    if "__annotations__" not in state.local_vars:
        state = state.set_local("__annotations__", {})
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
