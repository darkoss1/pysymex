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

"""Collection opcodes (lists, tuples, dicts, sets) for Python 3.11.

Each ``@opcode_handler`` entry registers CPython opcode names for this interpreter version and delegates semantics to :mod:`pysymex.execution.opcodes.common` (stack effects, forks, constraints, and limitations are documented on the common handlers)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatch.dispatcher import opcode_handler
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.build import (
    handle_common_build_const_key_map,
    handle_common_build_list,
    handle_common_build_map,
    handle_common_build_set,
    handle_common_build_slice,
    handle_common_build_string,
    handle_common_build_tuple,
)
from pysymex.execution.opcodes.common.collections.mutation import (
    handle_common_collection_update,
    handle_common_dict_merge_update,
    handle_common_list_append,
    handle_common_list_extend,
    handle_common_map_add,
    handle_common_set_add,
)
from pysymex.execution.opcodes.common.collections.subscript import (
    handle_common_binary_subscr,
    handle_common_delete_subscr,
    handle_common_store_subscr,
)
from pysymex.execution.opcodes.common.collections.unpack import (
    handle_common_unpack_ex,
    handle_common_unpack_sequence,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


@opcode_handler("BUILD_LIST")
def handle_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items."""
    return handle_common_build_list(instr, state, ctx)


@opcode_handler("BUILD_TUPLE")
def handle_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items."""
    return handle_common_build_tuple(instr, state, ctx)


@opcode_handler("BUILD_SET")
def handle_build_set(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a set from stack items."""
    return handle_common_build_set(instr, state, ctx)


@opcode_handler("BUILD_MAP")
def handle_build_map(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a dict from stack items."""
    return handle_common_build_map(instr, state, ctx)


@opcode_handler("BUILD_CONST_KEY_MAP")
def handle_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys."""
    return handle_common_build_const_key_map(instr, state, ctx)


@opcode_handler("BUILD_STRING")
def handle_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items."""
    return handle_common_build_string(instr, state, ctx)


@opcode_handler("BUILD_SLICE")
def handle_build_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a slice object."""
    return handle_common_build_slice(instr, state, ctx)


@opcode_handler("LIST_EXTEND")
def handle_list_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extend a list precisely."""
    return handle_common_list_extend(instr, state, ctx)


@opcode_handler("SET_UPDATE")
def handle_collection_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Basic update for other collections."""
    return handle_common_collection_update(instr, state, ctx)


@opcode_handler("LIST_APPEND")
def handle_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Append to a list."""
    return handle_common_list_append(instr, state, ctx)


@opcode_handler("SET_ADD")
def handle_set_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a set."""
    return handle_common_set_add(instr, state, ctx)


@opcode_handler("MAP_ADD")
def handle_map_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a dict."""
    return handle_common_map_add(instr, state, ctx)


@opcode_handler("BINARY_SUBSCR")
def handle_binary_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Subscript operation."""
    return handle_common_binary_subscr(instr, state, ctx)


@opcode_handler("STORE_SUBSCR")
def handle_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store subscript."""
    return handle_common_store_subscr(instr, state, ctx)


@opcode_handler("DELETE_SUBSCR")
def handle_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete subscript."""
    return handle_common_delete_subscr(instr, state, ctx)


@opcode_handler("UNPACK_SEQUENCE")
def handle_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack a sequence."""
    return handle_common_unpack_sequence(instr, state, ctx)


@opcode_handler("UNPACK_EX")
def handle_unpack_ex(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unpack with starred target."""
    return handle_common_unpack_ex(instr, state, ctx)


@opcode_handler("DICT_MERGE", "DICT_UPDATE")
def handle_dict_merge_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle DICT_MERGE and DICT_UPDATE."""
    return handle_common_dict_merge_update(instr, state, ctx)
