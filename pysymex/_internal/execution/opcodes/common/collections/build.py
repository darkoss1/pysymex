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
:class:`~pysymex._internal.execution.opcodes.common.lowering.CollectionLowerer`, and
applies constraints, heap updates, and feasible exception branches. Set and map
builds terminate with unsupported diagnostics when object hashing is required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.state.record import StateConstraints
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.slices import (
    SliceBounds,
    build_slice_value,
)
from pysymex._internal.core.types.stack_coercion import StackValuePolicy
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    may_be_feasible,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.hashability import (
    concrete_unhashable_type_error,
    requires_symbolic_object_hashing,
)
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


if TYPE_CHECKING:
    import dis
    from collections.abc import Iterable

    from pysymex._internal.core.solver.engine.results import SolverResult
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

BUILD_SET_EXCEPTION_FEASIBILITY_UNKNOWN = "build_set_exception_feasibility_unknown"


def _path_satisfiability_result(
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> SolverResult:
    return PathSatisfiability.result(constraints, known_sat_prefix_len=known_sat_prefix_len)


_BUILD_SET_EXCEPTION_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=BUILD_SET_EXCEPTION_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.collections",
    subject="BUILD_SET exception",
)


def _pop_stack_items(state: VMState, count: int) -> list[StackValue]:
    """Pop ``count`` operands and return them in their original left-to-right order."""
    if count <= 0:
        return []
    items = state.stack[-count:]
    del state.stack[-count:]
    state.invalidate_cached_hash()
    return items


def _pop_stack_pairs(state: VMState, count: int) -> list[tuple[StackValue, StackValue]]:
    """Pop ``count`` key/value pairs in their original mapping order."""
    if count <= 0:
        return []
    raw_items = state.stack[-(count * 2) :]
    del state.stack[-(count * 2) :]
    state.invalidate_cached_hash()
    return [(raw_items[index], raw_items[index + 1]) for index in range(0, len(raw_items), 2)]


def handle_common_build_list(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a list from stack items."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, count, "BUILD_LIST elements")
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
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a tuple from stack items."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, count, "BUILD_TUPLE elements")
    items = _pop_stack_items(state, count)

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_tuple(items)

    state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_set(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a set from stack items."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, count, "BUILD_SET elements")
    items = _pop_stack_items(state, count)
    type_error_message = _first_unhashable_type_error(items)
    if type_error_message is not None:
        return type_error_result(state, ctx, instr.offset, type_error_message)
    if any(requires_symbolic_object_hashing(item) for item in items):
        return _unsupported_hashed_collection(
            state,
            "set construction requires modeled object hashing",
        )

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_set(items)

    exception_result = _path_satisfiability_result(
        [*state.path_constraints.to_list(), lowered.exception_condition],
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_BUILD_SET_EXCEPTION_FEASIBILITY_SPEC,
        branches=[FeasibilityBranch("exception", exception_result)],
    )
    if may_be_feasible(exception_result):
        return CollectionStackOps.branch_or_terminate_exception(
            instr,
            state,
            ctx,
            lowered.exception_condition,
            fallback_events=fallback_events,
        )

    state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_map(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a dict from stack items."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, count * 2, "BUILD_MAP key/value pairs")
    items = _pop_stack_pairs(state, count)
    type_error_message = _first_unhashable_type_error(key for key, _value in items)
    if type_error_message is not None:
        return type_error_result(state, ctx, instr.offset, type_error_message)
    if any(requires_symbolic_object_hashing(key) for key, _value in items):
        return _unsupported_hashed_collection(
            state,
            "dict construction requires modeled object key hashing",
        )

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items)

    state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_const_key_map(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a dict with constant keys."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, 1 + count, "BUILD_CONST_KEY_MAP values and keys")

    keys_tuple = state.stack[-1]
    values = state.stack[-(count + 1) : -1]
    del state.stack[-(count + 1) :]
    state.invalidate_cached_hash()

    concrete_keys: list[StackValue] = []
    seq_keys = ConcreteExtractionPolicy.sequence(keys_tuple)
    if seq_keys is not None:
        concrete_keys = [StackValuePolicy.coerce(item) for item in seq_keys]

    items: list[tuple[StackValue, StackValue]] = []
    if len(concrete_keys) == len(values):
        items = list(zip(concrete_keys, values, strict=False))
        type_error_message = _first_unhashable_type_error(concrete_keys)
        if type_error_message is not None:
            return type_error_result(state, ctx, instr.offset, type_error_message)
        if any(requires_symbolic_object_hashing(key) for key in concrete_keys):
            return _unsupported_hashed_collection(
                state,
                "dict construction requires modeled object key hashing",
            )

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items, expected_count=count)

    state = CollectionStackOps.add_lowered_constraints(state, lowered.constraints)
    state = CollectionStackOps.apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_string(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Build a string from stack items."""
    count = int(instr.argval) if instr.argval else 0
    CollectionStackOps.require_depth(state, instr, count, "BUILD_STRING parts")
    items = _pop_stack_items(state, count)

    lowerer = CollectionLowerer(state.pc)
    result_sym = lowerer.build_string(items)

    state = state.push(result_sym)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_slice(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``BUILD_SLICE``: pop start/stop/step operands and push a slice carrier.

    Retains concrete bounds for native consumption when possible; otherwise lowers
    to a symbolic slice value with ``UNSUPPORTED_SLICE_ABSTRACTION`` degradation.
    """
    argc = int(instr.argval) if instr.argval else 2
    CollectionStackOps.require_depth(state, instr, argc, "BUILD_SLICE arguments")
    args = _pop_stack_items(state, argc)
    step = args[2] if argc == 3 else None
    sym_val, constraint = build_slice_value(SliceBounds(args[0], args[1], step), state.pc)
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _unsupported_hashed_collection(state: VMState, reason: str) -> OpcodeResult:
    """Return terminal degradation for unsupported modeled object hashing."""
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL],
        fallback_events=[
            CollectionFallbackEvents.unsupported_hashed_collection(
                state=state,
                reason=reason,
            ),
        ],
        terminal=True,
    )


def _first_unhashable_type_error(values: Iterable[object]) -> str | None:
    """Return the first definite unhashable operand TypeError from *values*."""
    for value in values:
        message = concrete_unhashable_type_error(value)
        if message is not None:
            return message
    return None
