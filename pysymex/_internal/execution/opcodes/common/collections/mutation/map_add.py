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

"""MAP_ADD dict-comprehension mutation opcode handler."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.hashability import (
    concrete_unhashable_type_error,
    requires_symbolic_object_hashing,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.writes import record_item_write
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_map_add(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``MAP_ADD``: associate a stack key with a value on a modeled dict.

    CPython stack effect: pops key then value; updates ``SymbolicDict`` when the
    container under the key slot is tracked.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(
        state,
        instr,
        index + 2,
        "MAP_ADD key/value and target container",
    )
    value = state.pop()
    key = state.pop()

    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicDict):
        type_error_message = concrete_unhashable_type_error(key)
        if type_error_message is not None:
            return type_error_result(state, ctx, instr.offset, type_error_message)
        if requires_symbolic_object_hashing(key):
            return _unsupported_map_add_hashing(state)
        new_dict = real_container.__setitem__(key, value)
        if container_addr is not None:
            state = state.store_heap(container_addr, new_dict)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_dict
            state = state.replace(stack=new_stack)
        state = record_item_write(state, write_location, instr)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _unsupported_map_add_hashing(state: VMState) -> OpcodeResult:
    """Advance with explicit degradation for unsupported ``MAP_ADD`` key hashing."""
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=[CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        reason="MAP_ADD key requires symbolic or modeled object hashing",
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        fallback_events=fallback_events,
    )
