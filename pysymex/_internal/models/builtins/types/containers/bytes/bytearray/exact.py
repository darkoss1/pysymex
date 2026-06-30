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

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.sources import IterationSources

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState


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
    items = IterationSources.iterable_items(source, state)
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


def retained_byte_items(items: Sequence[object]) -> list[object] | None:
    """Normalize bytearray items while preserving proved byte-valued symbols."""
    values: list[object] = []
    for item in items:
        byte_value = concrete_byte(item)
        if byte_value is not None:
            values.append(byte_value)
            continue
        if isinstance(item, SymbolicValue) and _is_proved_byte_symbol(item):
            values.append(item)
            continue
        return None
    return values


def _is_proved_byte_symbol(value: SymbolicValue) -> bool:
    if not z3.is_true(simplify_expr(z3.Or(value.is_int, value.is_bool))):
        return False
    min_value = value.min_val
    max_value = value.max_val
    return (
        isinstance(min_value, int)
        and isinstance(max_value, int)
        and 0 <= min_value
        and max_value <= 255
    )


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
    receiver.set_concrete_items(values)
    receiver.set_runtime_type("bytearray")


def bytearray_literal(values: Sequence[int]) -> SymbolicList:
    """Return a new bytearray-typed concrete-backed symbolic list."""
    result = SymbolicList.from_const(values)
    result.set_runtime_type("bytearray")
    return result
