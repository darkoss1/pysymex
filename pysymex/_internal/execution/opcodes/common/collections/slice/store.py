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

"""STORE_SLICE native exact mutation semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
    route_modeled_slice_index,
)
from pysymex._internal.execution.opcodes.common.collections.slice.replacement import (
    apply_slice_replacement_iterator_exhaustion,
    exact_slice_replacement_items,
    preserve_slice_target_type,
)
from pysymex._internal.execution.opcodes.common.collections.slice.shared import (
    concrete_binary_slice,
    record_slice_write,
    replace_direct_container_aliases,
    unsupported_slice_result,
)
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def handle_common_store_slice(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``STORE_SLICE``: assign into a container slice when modeling allows.

    CPython stack effect: pops value, slice, then container. Updates modeled lists or
    reports unsupported abstraction when bounds or container kinds are unknown.
    """
    CollectionStackOps.require_depth(
        state,
        instr,
        4,
        "STORE_SLICE container, start, stop, and value",
    )
    stop = state.pop()
    start = state.pop()
    container = state.pop()
    value = state.pop()
    preserved_operands: list[StackValue] = [value, container]
    protocol_result = route_modeled_slice_index(state, ctx, preserved_operands, start, stop)
    if protocol_result is not None:
        return protocol_result
    exact_result = _try_store_exact_slice(instr, state, value, container, start, stop)
    if exact_result is not None:
        return exact_result
    return unsupported_slice_result(
        state,
        reason="STORE_SLICE target, bounds, or replacement could not be mutated precisely",
    )


def _try_store_exact_slice(
    instr: dis.Instruction,
    state: VMState,
    value: StackValue,
    container: StackValue,
    start: StackValue,
    stop: StackValue,
) -> OpcodeResult | None:
    """Perform exact list slice assignment when bounds and replacement are concrete."""
    concrete_slice = concrete_binary_slice(start, stop)
    if concrete_slice is None:
        return None
    real_container, container_addr = _resolve_slice_target(container, state)
    replacement = exact_slice_replacement_items(value, state, real_container)
    if replacement is None:
        return None
    updated_items = _store_slice_items(real_container, concrete_slice, replacement)
    if updated_items is None:
        return None

    state = record_slice_write(state, container, instr)
    state = apply_slice_replacement_iterator_exhaustion(state, value)
    return _commit_exact_list_mutation(state, real_container, container_addr, updated_items)


def _resolve_slice_target(container: StackValue, state: VMState) -> tuple[object, int]:
    """Resolve a slice target and its heap address when it is heap backed."""
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container), container.address
    return SymbolicObject.resolve_runtime_container(container, state), -1


def _store_slice_items(
    container: object,
    key: slice,
    replacement: list[StackValue],
) -> list[object] | None:
    """Return concrete post-assignment list items for supported exact targets."""
    if isinstance(container, list):
        concrete_container = cast("list[object]", container)
        concrete_container[key] = list(replacement)
        return concrete_container
    if isinstance(container, SymbolicList) and container.concrete_items is not None:
        items = list(container.concrete_items)
        items[key] = list(replacement)
        return items
    return None


def _commit_exact_list_mutation(
    state: VMState,
    original_container: object,
    container_addr: int,
    items: list[object],
) -> OpcodeResult:
    """Persist exact list mutation and retarget aliases/source carriers."""
    if isinstance(original_container, list):
        return OpcodeResult.continue_with(state.advance_pc())

    built = CollectionLowerer(state.pc).build_list(cast("list[StackValue]", items))
    storage = preserve_slice_target_type(original_container, built.storage)
    state = CollectionStackOps.apply_heap_updates(state, built.heap_updates)
    if container_addr != -1:
        state = state.store_heap(container_addr, storage)
    state = replace_direct_container_aliases(state, original_container, storage)
    return OpcodeResult.continue_with(state.advance_pc())
