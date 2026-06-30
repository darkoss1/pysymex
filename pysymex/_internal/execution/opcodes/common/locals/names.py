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

"""Name-namespace handlers for non-fast locals and annotation setup."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.state.types import UNBOUND, is_bound
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.locals.stack_ops import LocalStackOps

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_load_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load name from locals or globals."""
    name = str(instr.argval)
    raw_value = state.get_local(name)
    value = raw_value if is_bound(raw_value) and raw_value is not None else state.get_global(name)
    if value is None:
        sym_val, type_constraint = SymbolicValue.symbolic(name)
        state = state.add_constraint(z3.Not(sym_val.is_none))

        state = state.set_local(name, sym_val)
        state = state.add_constraint(type_constraint)
        value = sym_val
    state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``STORE_NAME``: pop TOS into ``locals`` under ``instr.argval``.

    Creates or overwrites the named local. At root ``exec``/module scope, CPython
    uses one namespace for locals and globals, so root writes are also visible to
    nested functions that resolve the name through ``LOAD_GLOBAL``.
    """
    name = str(instr.argval)
    LocalStackOps.require_depth(state, instr, 1, "STORE_NAME value")
    value = state.pop()
    state = state.set_local(name, value)
    if not state.call_stack:
        state = state.set_global(name, value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
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


def handle_common_load_locals(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Push locals() dict onto stack."""
    locals_dict, constraint = SymbolicValue.symbolic(f"locals_{state.pc}")
    state = state.push(locals_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_setup_annotations(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Set up __annotations__ dict (class/module level annotations)."""
    if "__annotations__" not in state.local_vars:
        state = state.set_local("__annotations__", {})
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
