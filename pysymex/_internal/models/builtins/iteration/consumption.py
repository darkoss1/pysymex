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

"""Alias-visible consumption side effects for exact finite iterators."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.iterator_sources import ZipIteratorSource
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.builtins.iteration.sources import IterationSources

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def iterator_size_change_runtime_error(
    iterator: SymbolicIterator,
    state: VMState,
) -> bool:
    """Return whether CPython would reject advancing this mutated iterator."""
    if iterator.exhausted:
        return False
    if not iterator.size_change_raises or iterator.source_size is None:
        return False
    concrete_items = IterationSources.iterator_items(iterator, state)
    return concrete_items is not None and len(concrete_items) != iterator.source_size


def exhausted_iterator(
    iterator: SymbolicIterator,
    state: VMState,
) -> SymbolicIterator | None:
    """Return an iterator advanced to the end of its exact finite source."""
    if iterator.exhausted:
        return iterator
    concrete_items = IterationSources.iterator_items(iterator, state)
    if concrete_items is None:
        return None
    target_index = max(iterator.index, len(concrete_items))
    updated = iterator
    while updated.index < target_index:
        updated = updated.advance()
    return updated.exhaust()


def iterator_consumption_mutations(
    value: object,
    state: VMState,
) -> list[tuple[SymbolicIterator, SymbolicIterator]]:
    """Return iterator updates caused by fully consuming an exact finite iterator."""
    resolved = SymbolicObject.resolve(cast("StackValue", value), state)
    if not isinstance(resolved, SymbolicIterator) or resolved.is_generator:
        return []
    updated_iterator = exhausted_iterator(resolved, state)
    if updated_iterator is None:
        return []
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]] = []
    _append_iterator_mutation(mutations, resolved, updated_iterator)
    mutations.extend(_zip_source_iterator_mutations(resolved, state))
    return mutations


def iterator_mutation_side_effect(
    original_iterator: SymbolicIterator,
    updated_iterator: SymbolicIterator,
) -> dict[str, object]:
    """Return the modeled side effect for an alias-visible iterator update."""
    if (
        updated_iterator.index == original_iterator.index
        and updated_iterator.exhausted == original_iterator.exhausted
    ):
        return {}
    return {
        "iterator_mutation": {
            "original_iterator": original_iterator,
            "updated_iterator": updated_iterator,
        },
    }


def iterator_exhaustion_side_effect(
    value: object,
    state: VMState,
) -> dict[str, object] | None:
    """Return a mutation side effect for models that consume a finite iterator fully."""
    mutations = iterator_consumption_mutations(value, state)
    if not mutations:
        return None
    side_effects = iterator_mutation_side_effect(*mutations[0])
    if len(mutations) > 1:
        side_effects["iterator_source_mutations"] = [
            {
                "original_iterator": original,
                "updated_iterator": updated,
            }
            for original, updated in mutations[1:]
        ]
    return side_effects or None


def _zip_source_iterator_mutations(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[tuple[SymbolicIterator, SymbolicIterator]]:
    source = iterator.iterable
    if not isinstance(source, ZipIteratorSource) or iterator.index != 0:
        return []

    input_lengths: list[int] = []
    for iterable in source.iterables:
        items = IterationSources.iterable_items(iterable, state)
        if items is None:
            return []
        input_lengths.append(len(items))
    if not input_lengths:
        return []

    pair_count = min(input_lengths)
    first_stop_index = input_lengths.index(pair_count)
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]] = []
    for index, iterable in enumerate(source.iterables):
        resolved = SymbolicObject.resolve(cast("StackValue", iterable), state)
        if not isinstance(resolved, SymbolicIterator) or resolved.is_generator:
            continue
        advance_count = pair_count
        if index < first_stop_index and input_lengths[index] > pair_count:
            advance_count += 1
        updated = _advance_iterator(resolved, advance_count)
        if index == first_stop_index:
            updated = updated.exhaust()
        _append_iterator_mutation(mutations, resolved, updated)
    return mutations


def _advance_iterator(iterator: SymbolicIterator, count: int) -> SymbolicIterator:
    updated = iterator
    for _ in range(count):
        updated = updated.advance()
    return updated


def _append_iterator_mutation(
    mutations: list[tuple[SymbolicIterator, SymbolicIterator]],
    original: SymbolicIterator,
    updated: SymbolicIterator,
) -> None:
    if updated.index == original.index and updated.exhausted == original.exhausted:
        return
    mutations.append((original, updated))
