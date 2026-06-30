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

"""LIST_APPEND and LIST_EXTEND item mutation opcode handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.writes import record_item_write
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_list_extend(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``LIST_EXTEND``: append another iterable to a modeled list when precise.

    CPython stack effect: pops the iterable operand; mutates ``SymbolicList`` storage
    or heap alias when elements are concrete. Unsupported targets or iterable operands
    are reported as degraded collection mutation semantics.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(
        state,
        instr,
        index + 1,
        "LIST_EXTEND value and target container",
    )
    val = state.pop()
    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    real_value: object = val
    if isinstance(val, SymbolicObject):
        real_value = state.load_heap(val.address, val)

    if isinstance(real_container, SymbolicList):
        extend_source: SymbolicList | list[object] | tuple[object, ...] | None = None
        if isinstance(real_value, SymbolicList):
            extend_source = real_value
        else:
            seq = ConcreteExtractionPolicy.sequence(real_value)
            if seq is not None:
                extend_source = seq

        if extend_source is not None:
            new_container = real_container.extend(extend_source)
            if container_addr is not None:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)
            state = record_item_write(state, write_location, instr)
        else:
            return _unsupported_mutation(
                state,
                f"{instr.opname} source iterable is not retained as a concrete sequence",
            )
    else:
        return _unsupported_mutation(
            state,
            f"{instr.opname} target container is not a retained list",
        )

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_list_append(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``LIST_APPEND``: push one value onto a modeled or concrete list tail.

    CPython stack effect: pops the value operand; updates list storage in place when
    the container is a tracked ``SymbolicList`` or heap object.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(
        state,
        instr,
        index + 1,
        "LIST_APPEND value and target container",
    )
    val = state.pop()

    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicList):
        append_item, heap_updates = CollectionLowerer(state.pc).element_reference(val, {})
        for address, heap_value in heap_updates:
            state = state.store_heap(address, heap_value)
        new_list = real_container.append(append_item)
        if container_addr is not None:
            state = state.store_heap(container_addr, new_list)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_list
            state = state.replace(stack=new_stack)
        state = record_item_write(state, write_location, instr)
    else:
        return _unsupported_mutation(
            state,
            f"{instr.opname} target container is not a retained list",
        )
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _unsupported_mutation(state: VMState, reason: str) -> OpcodeResult:
    """Advance past a collection mutation whose target/source is unsupported."""
    return _degraded_mutation_result(
        state,
        degraded_pass=CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL,
        reason=reason,
    )


def _degraded_mutation_result(
    state: VMState,
    *,
    degraded_pass: str,
    reason: str,
) -> OpcodeResult:
    """Advance while recording explicit collection mutation degradation."""
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=[degraded_pass],
        reason=reason,
    )
    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=[degraded_pass],
        fallback_events=fallback_events,
    )
