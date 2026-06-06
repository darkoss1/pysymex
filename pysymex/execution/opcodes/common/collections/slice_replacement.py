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

"""Exact replacement extraction for native slice mutation opcodes."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.execution.opcodes.common.collections.helpers import (
    extract_concrete_sequence,
    resolve_runtime_container,
)
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    iterator_exhaustion_side_effect,
)
from pysymex.models.containers.bytes.bytearray.exact import concrete_byte_items

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


def exact_slice_replacement_items(
    value: StackValue,
    state: VMState,
    target: object,
) -> list[StackValue] | None:
    """Return concrete items CPython would iterate for slice replacement."""
    resolved = resolve_runtime_container(value, state)
    if _is_bytearray_target(target):
        raw_items = concrete_iterable_items(resolved, state)
        byte_items = concrete_byte_items(raw_items) if raw_items is not None else None
        return cast("list[StackValue] | None", byte_items)

    sequence = extract_concrete_sequence(resolved)
    if sequence is not None:
        return cast("list[StackValue]", list(sequence))
    return concrete_iterable_items(resolved, state)


def apply_slice_replacement_iterator_exhaustion(
    state: VMState,
    value: StackValue,
) -> VMState:
    """Propagate full iterator consumption caused by exact slice replacement."""
    side_effect = iterator_exhaustion_side_effect(value, state)
    if not side_effect:
        return state
    mutation = side_effect.get("iterator_mutation")
    if isinstance(mutation, Mapping):
        state = _apply_iterator_mutation(state, cast("Mapping[object, object]", mutation))
    source_mutations = side_effect.get("iterator_source_mutations")
    if isinstance(source_mutations, list):
        for source_mutation in cast("list[object]", source_mutations):
            if isinstance(source_mutation, Mapping):
                state = _apply_iterator_mutation(
                    state,
                    cast("Mapping[object, object]", source_mutation),
                )
    return state


def _apply_iterator_mutation(
    state: VMState,
    mutation: Mapping[object, object],
) -> VMState:
    mutation_mapping = cast("Mapping[str, object]", mutation)
    original_iterator = mutation_mapping.get("original_iterator")
    updated_iterator = mutation_mapping.get("updated_iterator")
    if original_iterator is None or updated_iterator is None:
        return state
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )

    return propagate_container_mutation_reference(
        state,
        original_iterator,
        cast("StackValue", updated_iterator),
    )


def preserve_slice_target_type(original: object, replacement: SymbolicList) -> SymbolicList:
    """Retain list-like runtime tags after rebuilding exact slice storage."""
    sequence_type = getattr(original, "_type", None)
    if not isinstance(sequence_type, str):
        return replacement
    return dataclasses.replace(replacement, _type=sequence_type)


def _is_bytearray_target(target: object) -> bool:
    return isinstance(target, SymbolicList) and getattr(target, "_type", None) == "bytearray"
