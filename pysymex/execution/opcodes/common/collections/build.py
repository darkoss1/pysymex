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

"""BUILD_* opcode handlers for lists, tuples, sets, maps, strings, and slices.

Pops stack operands per CPython arity, lowers construction through
:class:`~pysymex.execution.opcodes.common.lowering.CollectionLowerer`, and
applies constraints, heap updates, and feasible exception branches. Set and map
builds terminate with unsupported diagnostics when object hashing is required.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.fallbacks import (
    UNSUPPORTED_HASHED_COLLECTION_PROTOCOL,
    unsupported_hashed_collection_event,
)
from pysymex.execution.opcodes.common.collections.helpers import (
    add_lowered_constraints,
    apply_heap_updates,
    as_stack_value,
    branch_or_terminate_exception,
    extract_concrete_sequence,
    path_is_sat,
    require_stack_depth,
)
from pysymex.core.types.containers.slices import (
    SliceBounds,
    build_slice_value,
)
from pysymex.execution.opcodes.common.lowering import CollectionLowerer
from pysymex.models.objects import SymbolicInstance

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def _uses_modeled_object_hashing(value: object) -> bool:
    """Return whether native hashing would require user-instance semantics."""
    return isinstance(value, SymbolicInstance) or isinstance(
        getattr(value, "_modeled_object", None), SymbolicInstance
    )


def _pop_stack_items(state: VMState, count: int) -> list[StackValue]:
    """Pop ``count`` operands and return them in their original left-to-right order."""
    items = [state.pop() for _ in range(count)]
    items.reverse()
    return items


def handle_common_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, count, "BUILD_LIST elements")
    items = _pop_stack_items(state, count)

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_list(items)

    for address, value in lowered.heap_updates:
        state = state.store_heap(address, value)
    state = state.store_heap(lowered.handle.address, lowered.storage)

    state = state.push(lowered.handle)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, count, "BUILD_TUPLE elements")
    items = _pop_stack_items(state, count)

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_tuple(items)

    state = add_lowered_constraints(state, lowered.constraints)
    state = apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_set(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a set from stack items."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, count, "BUILD_SET elements")
    items = _pop_stack_items(state, count)
    if any(_uses_modeled_object_hashing(item) for item in items):
        return _unsupported_hashed_collection_result(
            state,
            "set construction requires modeled object hashing",
        )

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_set(items)

    if path_is_sat([*state.path_constraints.to_list(), lowered.exception_condition]):
        return branch_or_terminate_exception(instr, state, ctx, lowered.exception_condition)

    state = add_lowered_constraints(state, lowered.constraints)
    state = apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict from stack items."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, count * 2, "BUILD_MAP key/value pairs")
    items: list[tuple[StackValue, StackValue]] = []
    for _ in range(count):
        val = state.pop()
        key = state.pop()
        items.append((key, val))
    items.reverse()
    if any(_uses_modeled_object_hashing(key) for key, _value in items):
        return _unsupported_hashed_collection_result(
            state,
            "dict construction requires modeled object key hashing",
        )

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items)

    state = add_lowered_constraints(state, lowered.constraints)
    state = apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, 1 + count, "BUILD_CONST_KEY_MAP values and keys")

    keys_tuple = state.pop()
    values: list[StackValue] = []
    for _ in range(count):
        val = state.pop()
        values.append(val)
    values.reverse()

    concrete_keys: list[StackValue] = []
    seq_keys = extract_concrete_sequence(keys_tuple)
    if seq_keys is not None:
        concrete_keys = [as_stack_value(item) for item in seq_keys]

    items: list[tuple[StackValue, StackValue]] = []
    if len(concrete_keys) == len(values):
        items = list(zip(concrete_keys, values, strict=False))

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items, expected_count=count)

    state = add_lowered_constraints(state, lowered.constraints)
    state = apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items."""
    count = int(instr.argval) if instr.argval else 0
    require_stack_depth(state, instr, count, "BUILD_STRING parts")
    items = _pop_stack_items(state, count)

    lowerer = CollectionLowerer(state.pc)
    result_sym = lowerer.build_string(items)

    state = state.push(result_sym)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``BUILD_SLICE``: pop start/stop/step operands and push a slice carrier.

    Retains concrete bounds for native consumption when possible; otherwise lowers
    to a symbolic slice value with ``UNSUPPORTED_SLICE_ABSTRACTION`` degradation.
    """
    argc = int(instr.argval) if instr.argval else 2
    require_stack_depth(state, instr, argc, "BUILD_SLICE arguments")
    args = _pop_stack_items(state, argc)
    step = args[2] if argc == 3 else None
    sym_val, constraint = build_slice_value(SliceBounds(args[0], args[1], step), state.pc)
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _unsupported_hashed_collection_result(state: VMState, reason: str) -> OpcodeResult:
    """Return terminal degradation for unsupported modeled object hashing."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        fallback_events=[
            unsupported_hashed_collection_event(
                state=state,
                reason=reason,
            )
        ],
        terminal=True,
    )
