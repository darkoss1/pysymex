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
    May rewrite heap slots via :func:`~pysymex.execution.opcodes.common.collections.helpers.apply_heap_updates`.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import item_write_location
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    apply_heap_updates,
)
from pysymex.execution.opcodes.common.collections.fallbacks import unsupported_slice_event
from pysymex.execution.opcodes.common.collections.protocols import (
    dispatch_built_slice_index_protocol,
    dispatch_retained_slice_zero_step,
    retained_slice_value_error_result,
)
from pysymex.execution.opcodes.common.collections.slice_replacement import (
    apply_slice_replacement_iterator_exhaustion,
    exact_slice_replacement_items,
    preserve_slice_target_type,
)
from pysymex.core.types.containers.slices import (
    UNSUPPORTED_SLICE_ABSTRACTION,
    extract_slice_bounds,
)
from pysymex.core.solver.slices import materialize_concrete_slice
from pysymex.execution.opcodes.common.lowering import CollectionLowerer

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


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
        return _unsupported_result(
            state,
            reason="retained store-slice bounds or replacement could not be concretely lowered",
        )
    try:
        updated_items = _mutate_concrete_items(real_container, concrete_slice, replacement)
    except ValueError as exc:
        return retained_slice_value_error_result(instr, state, ctx, str(exc))
    if updated_items is None:
        return _unsupported_result(
            state,
            reason="retained store-slice target could not be mutated precisely",
        )
    state = _record_slice_write(state, container, instr)
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
        return _unsupported_result(
            state,
            reason="retained delete-slice bounds could not be concretely lowered",
        )
    updated_items = _delete_concrete_items(real_container, concrete_slice)
    if updated_items is None:
        return _unsupported_result(
            state,
            reason="retained delete-slice target could not be mutated precisely",
        )
    state = _record_slice_write(state, container, instr)
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
    state = apply_heap_updates(state, built.heap_updates)
    if container_addr != -1:
        state = state.store_heap(container_addr, storage)
    state = _replace_direct_container_aliases(state, container, storage)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _replace_direct_container_aliases(
    state: VMState,
    old_container: object,
    new_container: StackValue,
) -> VMState:
    """Refresh aliases and source carriers after retained-slice mutation."""
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(state, old_container, new_container)


def _record_slice_write(
    state: VMState,
    container: StackValue,
    instr: dis.Instruction,
) -> VMState:
    """Record a successful retained-slice mutation."""
    location = item_write_location(state, container)
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname)
    )


def _unsupported_result(state: VMState, *, reason: str) -> OpcodeResult:
    """Terminate with unsupported retained-slice abstraction degradation."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_SLICE_ABSTRACTION],
        fallback_events=[unsupported_slice_event(state=state, reason=reason)],
        terminal=True,
    )


__all__ = ["try_delete_retained_slice", "try_store_retained_slice"]
