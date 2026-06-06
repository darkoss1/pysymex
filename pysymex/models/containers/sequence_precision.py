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

"""Shared retained-item precision helpers for sequence operator models."""

from __future__ import annotations

import dataclasses

import z3

from pysymex.core.constants import Z3_ONE, Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue

# Keep materialized repeats bounded so precision does not create large retained payloads.
MAX_RETAINED_REPEAT_ITEMS = 32


def concatenate_concrete_backed_sequences(
    left: SymbolicList, right: SymbolicList
) -> SymbolicList | None:
    """Return an exact retained-item concatenation when both inputs are fully known."""
    left_items = exact_concrete_items(left)
    right_items = exact_concrete_items(right)
    if left_items is None or right_items is None:
        return None
    return SymbolicList.from_const([*left_items, *right_items])


def repeat_concrete_backed_sequence(value: SymbolicList, count: int) -> SymbolicList | None:
    """Return an exact retained-item repetition for bounded concrete repeat counts."""
    items = exact_concrete_items(value)
    if items is None:
        return None
    if count <= 0:
        return SymbolicList.from_const([])
    if len(items) * count > MAX_RETAINED_REPEAT_ITEMS:
        return None
    return SymbolicList.from_const(items * count)


def slice_concrete_backed_sequence(value: SymbolicList, key: slice) -> SymbolicList | None:
    """Return an exact retained-item slice when the input sequence is fully known."""
    items = exact_concrete_items(value)
    if items is None:
        return None
    result = SymbolicList.from_const(items[key])
    sequence_type = getattr(value, "_type", None) or "list"
    return dataclasses.replace(result, _type=sequence_type)


def exact_concrete_items(value: SymbolicList) -> list[object] | None:
    """Return retained items only when they describe the full concrete sequence length."""
    items = value.concrete_items
    if items is None:
        return None
    length = z3.simplify(value.z3_len)
    if not z3.is_int_value(length) or length.as_long() != len(items):
        return None
    return items


def concrete_repeat_count(value: object) -> int | None:
    """Return a concrete sequence repeat count when one is definitely known."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, SymbolicValue):
        return None
    concrete = value.value
    if isinstance(concrete, bool):
        return int(concrete)
    if isinstance(concrete, int):
        return concrete
    expr = z3.simplify(value.z3_int)
    if z3.is_int_value(expr):
        return expr.as_long()
    return None


def repeat_count_expr(value: object) -> z3.ArithRef | None:
    """Return an arithmetic repeat-count expression for concrete or symbolic integers."""
    if isinstance(value, bool):
        return Z3_ONE if value else Z3_ZERO
    if isinstance(value, int):
        return get_int_val(value)
    if isinstance(value, SymbolicValue):
        return value.z3_int
    return None
