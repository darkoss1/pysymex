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

"""Concrete and symbolic key normalization for symbolic dictionary storage."""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass
from typing import cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.numeric.int import SymbolicInt
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

UNRESOLVED_KEY = object()


@dataclass(frozen=True, eq=False)
class RetainedSymbolicKey:
    """Opaque retained dictionary key for symbolic-key assignments."""

    key: object

    def __hash__(self) -> int:
        """Hash by object identity so Python dict lookup never invokes symbolic equality."""
        return id(self)

    def __eq__(self, other: object) -> bool:
        """Retained symbolic keys only compare equal by identity."""
        return self is other


def concrete_lookup_key(key: object) -> object:
    """Return a concrete dictionary key or the unresolved-key sentinel."""
    tuple_key = _concrete_tuple_lookup_key(key)
    if tuple_key is not None:
        return tuple_key
    if isinstance(key, SymbolicNoneType):
        return None
    if isinstance(key, SymbolicString):
        if z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return UNRESOLVED_KEY
    if isinstance(key, SymbolicInt):
        if z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
        return UNRESOLVED_KEY
    if isinstance(key, SymbolicValue):
        if key.value is not None:
            return key.value
        if z3.is_true(key.is_none):
            return None
        if not z3.is_false(key.is_none) and z3.is_true(simplify_expr(key.is_none)):
            return None
        is_int = z3.is_true(key.is_int) or (
            not z3.is_false(key.is_int) and z3.is_true(simplify_expr(key.is_int))
        )
        if is_int and z3.is_int_value(key.z3_int):
            return key.z3_int.as_long()
        is_str = z3.is_true(key.is_str) or (
            not z3.is_false(key.is_str) and z3.is_true(simplify_expr(key.is_str))
        )
        if is_str and z3.is_string_value(key.z3_str):
            return key.z3_str.as_string()
        return UNRESOLVED_KEY
    return key


def retained_lookup_key(key: object) -> object:
    """Return a concrete or opaque symbolic key suitable for retention storage."""
    tuple_key = _retained_tuple_lookup_key(key)
    if tuple_key is not None:
        return tuple_key
    if isinstance(key, SymbolicString) and key.unified_value is not None:
        return RetainedSymbolicKey(key)
    concrete_key = concrete_lookup_key(key)
    if concrete_key is not UNRESOLVED_KEY:
        return concrete_key
    if isinstance(key, (SymbolicInt, SymbolicString, SymbolicValue)):
        return RetainedSymbolicKey(key)
    return UNRESOLVED_KEY


def _concrete_tuple_lookup_key(key: object) -> tuple[object, ...] | None:
    """Return a concrete tuple lookup key when every retained item is concrete."""
    items = _tuple_key_items(key)
    if items is None:
        return None
    concrete_items: list[object] = []
    for item in items:
        concrete_item = concrete_lookup_key(item)
        if concrete_item is UNRESOLVED_KEY or not isinstance(concrete_item, Hashable):
            return None
        concrete_items.append(concrete_item)
    return tuple(concrete_items)


def _retained_tuple_lookup_key(key: object) -> tuple[object, ...] | None:
    """Return a tuple key preserving opaque symbolic items for concrete retention."""
    items = _tuple_key_items(key)
    if items is None:
        return None
    retained_items: list[object] = []
    for item in items:
        retained_item = retained_lookup_key(item)
        if retained_item is UNRESOLVED_KEY or not isinstance(retained_item, Hashable):
            return None
        retained_items.append(retained_item)
    return tuple(retained_items)


def _tuple_key_items(key: object) -> tuple[object, ...] | None:
    """Return retained tuple key items for Python tuples and tuple-shaped carriers."""
    if isinstance(key, tuple):
        return cast("tuple[object, ...]", key)
    if isinstance(key, SymbolicList) and getattr(key, "_type", None) == "tuple":
        concrete_items = key.concrete_items
        if concrete_items is None:
            return None
        return tuple(concrete_items)
    return None


def symbolic_key_equals_concrete(key: object, concrete_key: object) -> z3.BoolRef | None:
    """Return a symbolic equality predicate against a supported concrete key."""
    if isinstance(concrete_key, RetainedSymbolicKey):
        return symbolic_key_equals_retained(key, concrete_key.key)

    if isinstance(key, SymbolicString):
        if isinstance(concrete_key, str):
            return key.z3_str == ConstraintValues.string(concrete_key)
        return Z3_FALSE

    if not isinstance(key, SymbolicValue):
        return None

    if concrete_key is None:
        return key.is_none
    if isinstance(concrete_key, bool):
        concrete_bool = Z3_TRUE if concrete_key else Z3_FALSE
        return z3.Or(
            z3.And(key.is_bool, key.z3_bool == concrete_bool),
            z3.And(key.is_int, key.z3_int == int(concrete_key)),
        )
    if isinstance(concrete_key, int):
        conditions = [z3.And(key.is_int, key.z3_int == concrete_key)]
        if concrete_key in (0, 1):
            concrete_bool = Z3_TRUE if concrete_key else Z3_FALSE
            conditions.append(z3.And(key.is_bool, key.z3_bool == concrete_bool))
        return z3.Or(*conditions)
    if isinstance(concrete_key, str):
        return z3.And(key.is_str, key.z3_str == ConstraintValues.string(concrete_key))
    return None


def symbolic_key_equals_retained(key: object, retained_key: object) -> z3.BoolRef | None:
    """Return a symbolic equality predicate against a retained symbolic key."""
    if isinstance(key, SymbolicString):
        if isinstance(retained_key, SymbolicString):
            unified = retained_key.unified_value
            if unified is not None:
                return symbolic_key_equals_retained(key, unified)
            return key.z3_str == retained_key.z3_str
        if isinstance(retained_key, SymbolicValue):
            return z3.And(retained_key.is_str, key.z3_str == retained_key.z3_str)
        return None

    if isinstance(key, SymbolicInt):
        if isinstance(retained_key, SymbolicInt):
            return key.z3_int == retained_key.z3_int
        if isinstance(retained_key, SymbolicValue):
            return z3.And(retained_key.is_int, key.z3_int == retained_key.z3_int)
        if isinstance(retained_key, SymbolicString) and retained_key.unified_value is not None:
            return symbolic_key_equals_retained(key, retained_key.unified_value)
        return None

    if not isinstance(key, SymbolicValue):
        return None

    if isinstance(retained_key, SymbolicInt):
        return z3.And(key.is_int, key.z3_int == retained_key.z3_int)
    if isinstance(retained_key, SymbolicString):
        unified = retained_key.unified_value
        if unified is not None:
            return symbolic_key_equals_retained(key, unified)
        return z3.And(key.is_str, key.z3_str == retained_key.z3_str)
    if isinstance(retained_key, SymbolicValue):
        return z3.Or(
            z3.And(key.is_none, retained_key.is_none),
            z3.And(key.is_bool, retained_key.is_bool, key.z3_bool == retained_key.z3_bool),
            z3.And(key.is_int, retained_key.is_int, key.z3_int == retained_key.z3_int),
            z3.And(key.is_str, retained_key.is_str, key.z3_str == retained_key.z3_str),
        )
    return None


def symbolic_storage_key(key: object) -> SymbolicString:
    """Return the Z3 string key used by dictionary array storage."""
    if isinstance(key, SymbolicString):
        return key
    concrete_key = concrete_lookup_key(key)
    storage_key = concrete_key if concrete_key is not UNRESOLVED_KEY else key
    return SymbolicString.from_const(str(storage_key))
