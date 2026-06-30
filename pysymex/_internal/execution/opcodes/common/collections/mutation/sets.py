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

"""SET_ADD and SET_UPDATE mutation opcode handlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.writes import record_item_write
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

_MISSING_SET_ELEMENT = object()


@dataclass(frozen=True)
class _SetMutationOutcome:
    """Result of attempting to model a concrete-backed set mutation."""

    updated: StackValue | None = None
    type_error: str | None = None
    degraded_pass: str | None = None
    degraded_reason: str | None = None


def handle_common_set_add(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``SET_ADD`` for concrete-backed modeled sets.

    CPython stack effect: pops the value operand; updates the retained set container
    when hashing is concrete. Symbolic hashing or non-retained targets degrade.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(state, instr, index + 1, "SET_ADD value and target container")
    value = state.pop()
    return _set_mutation_result(
        instr,
        state,
        ctx,
        index=index,
        outcome=_set_add_outcome(_real_container(state, index), value),
    )


def handle_common_set_update(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Execute ``SET_UPDATE`` for concrete-backed modeled sets.

    CPython stack effect: pops the iterable operand; updates retained set payloads
    when the iterable and element hashing are concrete. Unsupported iteration or
    hashing is surfaced as degraded execution.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(
        state,
        instr,
        index + 1,
        "SET_UPDATE value and target container",
    )
    value = state.pop()
    return _set_mutation_result(
        instr,
        state,
        ctx,
        index=index,
        outcome=_set_update_outcome(_real_container(state, index), value),
    )


def _set_mutation_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    index: int,
    outcome: _SetMutationOutcome,
) -> OpcodeResult:
    """Apply a set mutation outcome to the retained target container."""
    if outcome.type_error is not None:
        return type_error_result(state, ctx, instr.offset, outcome.type_error)
    if outcome.degraded_pass is not None and outcome.degraded_reason is not None:
        return _degraded_mutation_result(
            state,
            degraded_pass=outcome.degraded_pass,
            reason=outcome.degraded_reason,
        )

    if outcome.updated is not None:
        container = state.peek(index - 1)
        write_location = item_write_location(state, container)
        if isinstance(container, SymbolicObject):
            state = state.store_heap(container.address, outcome.updated)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = outcome.updated
            state = state.replace(stack=new_stack)
        state = record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _real_container(state: VMState, index: int) -> object:
    """Return the retained set target, resolving heap-backed object handles."""
    container = state.peek(index - 1)
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container)
    return container


def _set_add_outcome(container: object, value: object) -> _SetMutationOutcome:
    """Return the precise or degraded outcome for a retained concrete set add."""
    current = _retained_set_payload(container)
    if current is None:
        return _SetMutationOutcome(
            degraded_pass=CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL,
            degraded_reason="SET_ADD target container is not a retained concrete set",
        )

    return _mutated_set_outcome(
        current,
        [_concrete_set_element(value)],
        unsupported_hash_reason="SET_ADD element requires symbolic or modeled object hashing",
    )


def _set_update_outcome(container: object, value: object) -> _SetMutationOutcome:
    """Return the precise or degraded outcome for a retained concrete set update."""
    current = _retained_set_payload(container)
    if current is None:
        return _SetMutationOutcome(
            degraded_pass=CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL,
            degraded_reason="SET_UPDATE target container is not a retained concrete set",
        )

    elements = _set_update_elements(value)
    if elements is None:
        return _SetMutationOutcome(
            degraded_pass=CollectionFallbackEvents.UNSUPPORTED_COLLECTION_MUTATION_PROTOCOL,
            degraded_reason="SET_UPDATE source iterable is not retained as a concrete sequence or set",
        )

    return _mutated_set_outcome(
        current,
        [_concrete_set_element(element) for element in elements],
        unsupported_hash_reason="SET_UPDATE element requires symbolic or modeled object hashing",
    )


def _mutated_set_outcome(
    current: set[object],
    elements: list[object],
    *,
    unsupported_hash_reason: str,
) -> _SetMutationOutcome:
    """Return a retained set value after adding concrete elements."""
    if any(element is _MISSING_SET_ELEMENT for element in elements):
        return _SetMutationOutcome(
            degraded_pass=CollectionFallbackEvents.UNSUPPORTED_HASHED_COLLECTION_PROTOCOL,
            degraded_reason=unsupported_hash_reason,
        )

    updated_payload: set[object] = set(current)
    for element in elements:
        try:
            updated_payload.add(element)
        except TypeError:
            return _SetMutationOutcome(type_error=f"unhashable type: '{type(element).__name__}'")

    updated = SymbolicValue.from_const(updated_payload)
    updated.set_runtime_type("set")
    updated.z3_int = ConstraintValues.int(len(updated_payload))
    updated.clear_hash_cache()
    return _SetMutationOutcome(updated=cast("StackValue", updated))


def _retained_set_payload(container: object) -> set[object] | None:
    """Return a copy of a concrete set retained by a modeled set carrier."""
    if isinstance(container, SymbolicValue):
        payload = container.value
        if isinstance(payload, set):
            return set(cast("set[object]", payload))
    return None


def _set_update_elements(value: object) -> list[object] | None:
    """Return concrete elements consumed by ``SET_UPDATE`` when retained."""
    source_set = _retained_set_payload(value)
    if source_set is not None:
        return list(source_set)
    sequence = ConcreteExtractionPolicy.sequence(value)
    if sequence is not None:
        return list(sequence)
    if isinstance(value, str):
        return list(value)
    if isinstance(value, bytes):
        return list(value)
    return None


def _concrete_set_element(value: object) -> object:
    """Return a concrete set element or a sentinel when hashing is unsupported."""
    if isinstance(value, SymbolicValue):
        concrete_value = value.value
        if concrete_value is not None:
            return concrete_value
        return _MISSING_SET_ELEMENT
    if isinstance(value, (bool, int, str, float, bytes, type)) or value is None:
        return value
    if isinstance(value, tuple):
        return cast("tuple[object, ...]", value)
    if isinstance(value, list):
        return cast("list[object]", value)
    if isinstance(value, dict):
        return cast("dict[object, object]", value)
    if isinstance(value, set):
        return cast("set[object]", value)
    return _MISSING_SET_ELEMENT


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
