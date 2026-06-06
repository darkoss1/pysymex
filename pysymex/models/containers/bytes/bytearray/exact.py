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

"""Exact bytearray payload helpers shared by mutation models."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.iterator_items import concrete_iterable_items

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def concrete_byte(value: object) -> int | None:
    """Return a concrete CPython byte value for exact integer-like inputs."""
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and 0 <= value <= 255:
        return value
    return None


def concrete_byte_values(source: object, state: VMState) -> list[int] | None:
    """Return exact bytes produced by iterating a finite bytearray source."""
    items = concrete_iterable_items(source, state)
    if items is None:
        return None
    return concrete_byte_items(items)


def concrete_byte_items(items: Sequence[object]) -> list[int] | None:
    """Normalize retained concrete bytearray items to integer byte values."""
    values: list[int] = []
    for item in items:
        byte_value = concrete_byte(item)
        if byte_value is None:
            return None
        values.append(byte_value)
    return values


def concrete_index(value: object) -> int | None:
    """Return a concrete integer index when the argument is exactly known."""
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def replace_exact_bytearray(receiver: SymbolicList, values: Sequence[int]) -> None:
    """Mutate a bytearray carrier to exactly represent ``values``."""
    exact = bytearray_literal(values)
    receiver.z3_array = exact.z3_array
    receiver.z3_len = exact.z3_len
    setattr(receiver, "_concrete_items", list(values))
    setattr(receiver, "_type", "bytearray")


def bytearray_literal(values: Sequence[int]) -> SymbolicList:
    """Return a new bytearray-typed concrete-backed symbolic list."""
    result = SymbolicList.from_const(values)
    setattr(result, "_type", "bytearray")
    return result
