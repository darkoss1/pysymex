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

"""Local and global variable opcodes (Python 3.11).

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex._internal.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.dispatcher.decorators import opcode_handler
from pysymex._internal.execution.opcodes.common.locals.closure import (
    handle_common_cell_ops,
    handle_common_copy_free_vars,
    handle_common_delete_deref,
    handle_common_load_closure,
    handle_common_load_deref,
    handle_common_store_deref,
)
from pysymex._internal.execution.opcodes.common.locals.constants import handle_common_load_const
from pysymex._internal.execution.opcodes.common.locals.fast import (
    handle_common_delete_fast,
    handle_common_load_fast_check,
    handle_common_store_fast,
)
from pysymex._internal.execution.opcodes.common.locals.globals import (
    handle_common_delete_global,
    handle_common_load_global,
    handle_common_store_global,
)
from pysymex._internal.execution.opcodes.common.locals.names import (
    handle_common_delete_name,
    handle_common_load_name,
    handle_common_setup_annotations,
    handle_common_store_name,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult


@opcode_handler("LOAD_CONST")
def handle_py311_load_const(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a constant onto the stack."""
    return handle_common_load_const(instr, state, ctx)


@opcode_handler("LOAD_FAST")
def handle_py311_load_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a local variable, raising for unbound fast locals on Python 3.11."""
    return handle_common_load_fast_check(instr, state, ctx)


@opcode_handler("STORE_FAST")
def handle_py311_store_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store top of stack into local variable."""
    return handle_common_store_fast(instr, state, ctx)


@opcode_handler("DELETE_FAST")
def handle_py311_delete_fast(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delete a local variable."""
    return handle_common_delete_fast(instr, state, ctx)


@opcode_handler("LOAD_GLOBAL")
def handle_py311_load_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load a global variable onto the stack."""
    return handle_common_load_global(instr, state, ctx)


@opcode_handler("STORE_GLOBAL")
def handle_py311_store_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store top of stack into a global variable."""
    return handle_common_store_global(instr, state, ctx)


@opcode_handler("DELETE_GLOBAL")
def handle_py311_delete_global(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delete a global variable."""
    return handle_common_delete_global(instr, state, ctx)


@opcode_handler("LOAD_NAME")
def handle_py311_load_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load name from locals or globals."""
    return handle_common_load_name(instr, state, ctx)


@opcode_handler("STORE_NAME")
def handle_py311_store_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store name in locals."""
    return handle_common_store_name(instr, state, ctx)


@opcode_handler("DELETE_NAME")
def handle_py311_delete_name(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delete a name."""
    return handle_common_delete_name(instr, state, ctx)


@opcode_handler("LOAD_DEREF", "LOAD_CLOSURE", "LOAD_CLASSDEREF")
def handle_py311_load_deref(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load from closure/free variable."""
    return handle_common_load_deref(instr, state, ctx)


@opcode_handler("LOAD_CLASSDEREF")
def handle_py311_load_classderef(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load class deref."""
    return handle_common_load_deref(instr, state, ctx)


@opcode_handler("LOAD_CLOSURE")
def handle_py311_load_closure(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Load closure cell."""
    return handle_common_load_closure(instr, state, ctx)


@opcode_handler("COPY_FREE_VARS")
def handle_py311_copy_free_vars(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Copy free variables."""
    return handle_common_copy_free_vars(instr, state, ctx)


@opcode_handler("SETUP_ANNOTATIONS")
def handle_py311_setup_annotations(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Setup annotations."""
    return handle_common_setup_annotations(instr, state, ctx)


@opcode_handler("STORE_DEREF")
def handle_py311_store_deref(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Store into closure variable."""
    return handle_common_store_deref(instr, state, ctx)


@opcode_handler("MAKE_CELL", "COPY_FREE_VARS")
def handle_py311_cell_ops(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Cell creation - mostly no-op for symbolic execution."""
    return handle_common_cell_ops(instr, state, ctx)


@opcode_handler("DELETE_DEREF")
def handle_py311_delete_deref(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Delete closure variable."""
    return handle_common_delete_deref(instr, state, ctx)


handle_load_const = handle_py311_load_const
handle_load_fast = handle_py311_load_fast
handle_store_fast = handle_py311_store_fast
handle_delete_fast = handle_py311_delete_fast
handle_load_global = handle_py311_load_global
handle_store_global = handle_py311_store_global
handle_delete_global = handle_py311_delete_global
handle_load_name = handle_py311_load_name
handle_store_name = handle_py311_store_name
handle_delete_name = handle_py311_delete_name
handle_load_deref = handle_py311_load_deref
handle_load_classderef = handle_py311_load_classderef
handle_load_closure = handle_py311_load_closure
handle_copy_free_vars = handle_py311_copy_free_vars
handle_setup_annotations = handle_py311_setup_annotations
handle_store_deref = handle_py311_store_deref
handle_cell_ops = handle_py311_cell_ops
handle_delete_deref = handle_py311_delete_deref
