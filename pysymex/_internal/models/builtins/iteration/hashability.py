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

"""Exact hashability checks for iterator-fed container construction."""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.models.builtins.iteration.sources import IterationSources

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def contains_definitely_unhashable_item(
    items: Iterable[object],
    state: VMState | None = None,
) -> bool:
    """Return whether exact items include a CPython-unhashable member."""
    return any(is_definitely_unhashable_item(item, state) for item in items)


def exact_dict_items_from_iterable(
    items: list[StackValue],
    state: VMState,
) -> dict[object, object] | None:
    """Return exact dict update pairs from materialized iterable items."""
    result: dict[object, object] = {}
    for item in items:
        pair = IterationSources.iterable_items(item, state)
        if pair is None or len(pair) != 2:
            return None
        key, value = pair
        if is_definitely_unhashable_item(key, state):
            return None
        result[key] = value
    return result


def exact_dict_items_error(
    items: list[StackValue],
    state: VMState,
) -> Literal["type", "value"] | None:
    """Classify a definite CPython dict-construction failure for exact items."""
    for item in items:
        pair = IterationSources.iterable_items(item, state)
        if pair is None:
            payload = SymbolicObject.resolve(item, state)
            if payload is None or type(payload) in (int, float, bool):
                return "type"
            continue
        if len(pair) != 2:
            return "value"
        if is_definitely_unhashable_item(pair[0], state):
            return "type"
    return None


def is_definitely_unhashable_item(item: object, state: VMState | None = None) -> bool:
    """Return whether an exact item is known to fail CPython hash-based containers."""
    if state is not None:
        item = SymbolicObject.resolve(cast("StackValue", item), state)
    payload = IterationSources.payload(item)
    if payload is not item:
        return is_definitely_unhashable_item(payload, state)
    if isinstance(payload, (SymbolicList, SymbolicDict, SymbolicSet)):
        return True
    if isinstance(payload, (list, dict, set, bytearray)):
        return True
    if isinstance(payload, (tuple, frozenset)):
        return any(
            is_definitely_unhashable_item(member, state)
            for member in cast("Iterable[object]", payload)
        )
    if not isinstance(payload, Hashable):
        return True
    try:
        hash(payload)
    except TypeError:
        return True
    return False
