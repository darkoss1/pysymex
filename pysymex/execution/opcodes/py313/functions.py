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

"""Call, import, and attribute opcode wrappers for Python 3.13.

Registers ``CALL``/``CALL_KW`` (with inline ``KW_NAMES`` handling),
``SET_FUNCTION_ATTRIBUTE``, ``LOAD_SUPER_*``, imports, and ``MAKE_FUNCTION``,
delegating to :mod:`pysymex.execution.opcodes.common.functions`. Does not own
builtin/stdlib models, sandbox import policy, or inter-procedural summaries.
.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions import (
    coerce_kw_names,
    handle_common_call,
    handle_common_call_function_ex,
    handle_common_delete_attr,
    handle_common_import_from,
    handle_common_import_name,
    handle_common_import_star,
    handle_common_kw_names,
    handle_common_load_build_class,
    handle_common_load_method,
    handle_common_load_super_attr,
    handle_common_load_super_variants,
    handle_common_make_function,
    handle_common_set_function_attribute,
    handle_common_store_attr,
)


if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_kw_names(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle KW_NAMES."""
    return handle_common_kw_names(instr, state, ctx)


def handle_import_star(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle IMPORT_STAR."""
    return handle_common_import_star(instr, state, ctx)


@opcode_handler("CALL", "CALL_KW")
def handle_call(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls."""
    if instr.opname == "CALL_KW":
        kw_names_raw: object = state.pop()
        kw_names = coerce_kw_names(kw_names_raw)
        state.pending_kw_names = kw_names if kw_names else None
    return handle_common_call(instr, state, ctx)


@opcode_handler("LOAD_METHOD", "LOAD_ATTR")
def handle_load_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load an attribute or method."""
    return handle_common_load_method(instr, state, ctx)


@opcode_handler("STORE_ATTR")
def handle_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object."""
    return handle_common_store_attr(instr, state, ctx)


@opcode_handler("DELETE_ATTR")
def handle_delete_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete attribute from object."""
    return handle_common_delete_attr(instr, state, ctx)


@opcode_handler("MAKE_FUNCTION")
def handle_make_function(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Create a function object."""
    return handle_common_make_function(instr, state, ctx)


@opcode_handler("LOAD_BUILD_CLASS")
def handle_load_build_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load __build_class__ builtin."""
    return handle_common_load_build_class(instr, state, ctx)


@opcode_handler("IMPORT_NAME")
def handle_import_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import a module (import x)."""
    return handle_common_import_name(instr, state, ctx)


@opcode_handler("IMPORT_FROM")
def handle_import_from(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import attribute from module (from x import y)."""
    return handle_common_import_from(instr, state, ctx)


@opcode_handler("LOAD_SUPER_ATTR")
def handle_load_super_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load attribute from super() (Python 3.12+)."""
    return handle_common_load_super_attr(instr, state, ctx)


@opcode_handler("LOAD_SUPER_METHOD", "LOAD_ZERO_SUPER_ATTR", "LOAD_ZERO_SUPER_METHOD")
def handle_load_super_variants(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load method/attribute from super() variants (Python 3.12+)."""
    return handle_common_load_super_variants(instr, state, ctx)


@opcode_handler("CALL_FUNCTION_EX")
def handle_call_function_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle CALL_FUNCTION_EX (Python 3.11+)."""
    return handle_common_call_function_ex(instr, state, ctx)


@opcode_handler("SET_FUNCTION_ATTRIBUTE")
def handle_set_function_attribute(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle SET_FUNCTION_ATTRIBUTE (Python 3.13+)."""
    return handle_common_set_function_attribute(instr, state, ctx)
