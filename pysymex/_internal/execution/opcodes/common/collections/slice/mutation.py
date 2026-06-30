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

"""Apply concrete list mutations after retained-slice subscript execution.

When ``STORE_SUBSCR`` / ``DELETE_SUBSCR`` use a ``BUILD_SLICE`` key with fully concrete
bounds and sequence payload, mutates the backing container in place and commits heap
updates. Returns ``None`` to fall back to generic subscript lowering when precision is
insufficient.

Side Effects:
    May rewrite heap slots via :meth:`~pysymex._internal.execution.opcodes.common.collections.stack_ops.CollectionStackOps.CollectionStackOps.apply_heap_updates`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.solver.slices import materialize_concrete_slice
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.slices import (
    extract_slice_bounds,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
    dispatch_built_slice_index_protocol,
)
from pysymex._internal.execution.opcodes.common.collections.protocols.slices import (
    dispatch_retained_slice_zero_step,
    retained_slice_value_error_result,
)
from pysymex._internal.execution.opcodes.common.collections.slice.replacement import (
    apply_slice_replacement_iterator_exhaustion,
    exact_slice_replacement_items,
    preserve_slice_target_type,
)
from pysymex._internal.execution.opcodes.common.collections.slice.shared import (
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


def try_store_retained_slice(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    value: StackValue,
    container: StackValue,
    real_container: object,
    container_addr: int,
    key: StackValue,
) -> OpcodeResult | None:
    """Execute and then precisely mutate a supported retained store slice."""
    if not isinstance(key, SymbolicValue):
        return None
    dispatched = dispatch_built_slice_index_protocol(state, ctx, [value, container], key)
    if dispatched is not None:
        return dispatched
    if extract_slice_bounds(key) is None:
        return None
    zero_step_result = dispatch_retained_slice_zero_step(instr, state, ctx, key)
    if zero_step_result is not None:
        return zero_step_result
    concrete_slice = materialize_concrete_slice(key, state.path_constraints.to_list())
    replacement = exact_slice_replacement_items(value, state, real_container)
    if concrete_slice is None or replacement is None:
        return unsupported_slice_result(
            state,
            reason="retained store-slice bounds or replacement could not be concretely lowered",
        )
    try:
        updated_items = _mutate_concrete_items(real_container, concrete_slice, replacement)
    except ValueError as exc:
        return retained_slice_value_error_result(instr, state, ctx, str(exc))
    if updated_items is None:
        return unsupported_slice_result(
            state,
            reason="retained store-slice target could not be mutated precisely",
        )
    state = record_slice_write(state, container, instr)
    state = apply_slice_replacement_iterator_exhaustion(state, value)
    return _commit_mutation(state, real_container, container_addr, updated_items)


def try_delete_retained_slice(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    container: StackValue,
    real_container: object,
    container_addr: int,
    key: StackValue,
) -> OpcodeResult | None:
    """Execute and then precisely mutate a supported retained delete slice."""
    if not isinstance(key, SymbolicValue):
        return None
    dispatched = dispatch_built_slice_index_protocol(state, ctx, [container], key)
    if dispatched is not None:
        return dispatched
    if extract_slice_bounds(key) is None:
        return None
    zero_step_result = dispatch_retained_slice_zero_step(instr, state, ctx, key)
    if zero_step_result is not None:
        return zero_step_result
    concrete_slice = materialize_concrete_slice(key, state.path_constraints.to_list())
    if concrete_slice is None:
        return unsupported_slice_result(
            state,
            reason="retained delete-slice bounds could not be concretely lowered",
        )
    updated_items = _delete_concrete_items(real_container, concrete_slice)
    if updated_items is None:
        return unsupported_slice_result(
            state,
            reason="retained delete-slice target could not be mutated precisely",
        )
    state = record_slice_write(state, container, instr)
    return _commit_mutation(state, real_container, container_addr, updated_items)


def _mutate_concrete_items(
    container: object,
    key: slice,
    replacement: list[StackValue],
) -> list[object] | None:
    """Assign replacement items through a concrete slice on list storage."""
    items = _concrete_items(container)
    if items is None:
        return None
    items[key] = list(replacement)
    return items


def _delete_concrete_items(container: object, key: slice) -> list[object] | None:
    """Delete a concrete slice range from list storage."""
    items = _concrete_items(container)
    if items is None:
        return None
    del items[key]
    return items


def _concrete_items(container: object) -> list[object] | None:
    """Return a mutable concrete item list backing the container, if available."""
    if isinstance(container, list):
        return cast("list[object]", container)
    if isinstance(container, SymbolicList) and container.concrete_items is not None:
        return list(container.concrete_items)
    return None


def _commit_mutation(
    state: VMState,
    container: object,
    container_addr: int,
    items: list[object],
) -> OpcodeResult:
    """Advance the VM and persist heap updates after a concrete slice mutation."""
    if isinstance(container, list):
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    built = CollectionLowerer(state.pc).build_list(cast("list[StackValue]", items))
    storage = preserve_slice_target_type(container, built.storage)
    state = CollectionStackOps.apply_heap_updates(state, built.heap_updates)
    if container_addr != -1:
        state = state.store_heap(container_addr, storage)
    state = replace_direct_container_aliases(state, container, storage)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
