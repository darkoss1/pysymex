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

"""Exact finite iterable and iterator source materialization."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    FilterIteratorSource,
    MapIteratorSource,
    ZipIteratorSource,
)
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.predicates.evaluator import (
    filter_item_truth,
    realize_single_iterable_map,
    supports_exact_filter_predicate,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _iterator_items(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[StackValue] | None:
    """Return all exact source items for a finite iterator, independent of index."""
    if iterator.exhausted:
        return []
    iterable = IterationSources.payload(
        SymbolicObject.resolve(cast("StackValue", iterator.iterable), state),
    )
    items = IterationSources.iterable_items(iterable, state)
    if items is not None and iterator.reverse:
        return _reversed_iterator_items(iterator, items)
    return items


def _iterable_items(value: object, state: VMState) -> list[StackValue] | None:
    """Return exact CPython iteration items for a finite non-consuming iterable."""
    iterable = IterationSources.payload(SymbolicObject.resolve(cast("StackValue", value), state))
    if isinstance(iterable, SymbolicIterator):
        return IterationSources.remaining_iterator_items(iterable, state)
    return _concrete_source_items(iterable, state)


def _payload(value: object) -> object:
    """Unwrap retained literal iterable payloads carried by generic symbolic values."""
    if isinstance(value, SymbolicValue):
        payload = getattr(value, "_modeled_object", None)
        if isinstance(payload, (str, bytes, bytearray)):
            return payload
        if isinstance(payload, list):
            return cast("list[object]", payload)
        if isinstance(payload, tuple):
            return cast("tuple[object, ...]", payload)
        if isinstance(payload, dict):
            return cast("dict[object, object]", payload)
        if isinstance(payload, set):
            return cast("set[object]", payload)
        if isinstance(payload, frozenset):
            return cast("frozenset[object]", payload)
    return value


def _truth_filter_list(
    iterator: SymbolicIterator,
    state: VMState,
    name: str,
) -> tuple[SymbolicList, SymbolicIterator] | None:
    """Return a precise one-item list(filter(None, source)) result when possible."""
    source = iterator.iterable
    if not isinstance(source, FilterIteratorSource) or iterator.index != 0:
        return None
    if not supports_exact_filter_predicate(source.predicate):
        return None
    items = IterationSources.iterable_items(source.iterable, state)
    if items is None or len(items) != 1:
        return None
    item = items[0]
    truth_item = SymbolicObject.resolve(item, state)
    truth = filter_item_truth(source.predicate, truth_item)
    if truth is None:
        return None

    simplified_truth = simplify_expr(truth)
    if z3.is_true(simplified_truth):
        return SymbolicList.from_const([item]), iterator.advance()
    if z3.is_false(simplified_truth):
        return SymbolicList.from_const([]), iterator.advance()

    z3_array = z3.Store(
        z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort()),
        0,
        _item_storage_expr(item, name),
    )
    z3_len = z3.If(truth, ConstraintValues.int(1), Z3_ZERO)
    return (
        SymbolicList(
            name,
            z3_array=cast("z3.ArrayRef", z3_array),
            z3_len=z3_len,
            element_type="any",
        ),
        iterator.advance(),
    )


def _concrete_source_items(iterable: object, state: VMState) -> list[StackValue] | None:
    if isinstance(iterable, EnumerateIteratorSource):
        return _concrete_enumerate_items(iterable, state)
    if isinstance(iterable, ZipIteratorSource):
        return _concrete_zip_items(iterable, state)
    if isinstance(iterable, MapIteratorSource):
        return _concrete_map_items(iterable, state)
    if isinstance(iterable, FilterIteratorSource):
        return _concrete_filter_items(iterable, state)
    if isinstance(iterable, SymbolicList):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicDict):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(tuple(concrete_items.keys()))
    if isinstance(iterable, SymbolicDictView):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicSet):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return _stack_values_from_iterable(concrete_items)
    if isinstance(iterable, SymbolicBytes):
        concrete_value = iterable.concrete_value
        if concrete_value is None:
            return None
        return _stack_values_from_iterable(concrete_value)
    if isinstance(iterable, SymbolicString):
        if not z3.is_string_value(iterable.z3_str):
            return None
        try:
            concrete_value = iterable.z3_str.as_string()
        except z3.Z3Exception:
            return None
        return _stack_values_from_iterable(concrete_value)
    if isinstance(iterable, dict):
        return _stack_values_from_iterable(tuple(cast("dict[object, object]", iterable).keys()))
    if isinstance(iterable, (set, frozenset)):
        return _stack_values_from_iterable(cast("Iterable[object]", iterable))
    if isinstance(iterable, (str, bytes, bytearray, list, tuple)):
        return _stack_values_from_iterable(cast("Iterable[object]", iterable))
    return None


def _concrete_enumerate_items(
    source: EnumerateIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    items = IterationSources.iterable_items(source.iterable, state)
    if items is None:
        return None
    pairs = ((source.start + index, item) for index, item in enumerate(items))
    return _stack_values_from_iterable(pairs)


def _concrete_zip_items(
    source: ZipIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    materialized_inputs: list[list[StackValue]] = []
    for iterable in source.iterables:
        items = IterationSources.iterable_items(iterable, state)
        if items is None:
            return None
        materialized_inputs.append(items)
    pairs = (tuple(items) for items in zip(*materialized_inputs, strict=False))
    return _stack_values_from_iterable(pairs)


def _concrete_map_items(
    source: MapIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    items = IterationSources.iterable_items(source.iterable, state)
    if items is None:
        return None
    mapped_items = realize_single_iterable_map(source.function, list(items))
    if mapped_items is None:
        return None
    return _stack_values_from_iterable(mapped_items)


def _concrete_filter_items(
    source: FilterIteratorSource,
    state: VMState,
) -> list[StackValue] | None:
    if not supports_exact_filter_predicate(source.predicate):
        return None
    items = IterationSources.iterable_items(source.iterable, state)
    if items is None:
        return None
    filtered_items: list[StackValue] = []
    for item in items:
        truth_item = SymbolicObject.resolve(item, state)
        truth = filter_item_truth(source.predicate, truth_item)
        if truth is None:
            return None
        simplified_truth = simplify_expr(truth)
        if z3.is_true(simplified_truth):
            filtered_items.append(item)
        elif not z3.is_false(simplified_truth):
            return None
    return filtered_items


def _reversed_iterator_items(
    iterator: SymbolicIterator,
    items: list[StackValue],
) -> list[StackValue]:
    if iterator.source_size is None:
        return list(reversed(items))
    source_index = iterator.source_size - 1 - iterator.index
    if source_index < 0 or source_index >= len(items):
        return []
    return [items[index] for index in range(source_index, -1, -1)]


def _remaining_iterator_items(
    iterator: SymbolicIterator,
    state: VMState,
) -> list[StackValue] | None:
    """Return exact items that remain from the iterator's current index."""
    if iterator.exhausted:
        return []
    concrete_items = IterationSources.iterator_items(iterator, state)
    if concrete_items is None:
        return None
    if iterator.index < 0:
        return None
    return concrete_items[iterator.index :]


def _stack_values_from_iterable(items: Iterable[object]) -> list[StackValue]:
    return [cast("StackValue", item) for item in items]


def _item_storage_expr(value: object, name: str) -> z3.ArithRef:
    if isinstance(value, SymbolicValue):
        return ContainerStorageOps.storage_int_expr(value.z3_int, f"{name}_elem")
    if isinstance(value, bool):
        return ConstraintValues.int(int(value))
    if isinstance(value, int):
        return ConstraintValues.int(value)
    return Z3_ZERO


class IterationSources:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    iterator_items = staticmethod(_iterator_items)
    iterable_items = staticmethod(_iterable_items)
    payload = staticmethod(_payload)
    truth_filter_list = staticmethod(_truth_filter_list)
    remaining_iterator_items = staticmethod(_remaining_iterator_items)
