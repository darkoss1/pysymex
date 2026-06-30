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

"""Capability queries shared by symbolic execution and analysis callers."""

from __future__ import annotations

from collections.abc import Sized

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.affinity import AffinityKind, normalize_affinity
from pysymex._internal.core.types.base import SymbolicType


def length_expr(value: object) -> z3.ArithRef | None:
    """Return an exact or symbolic Python length expression when supported."""
    if isinstance(value, SymbolicType):
        return value.symbolic_length()
    if isinstance(value, Sized):
        try:
            return ConstraintValues.int(len(value))
        except (OverflowError, TypeError, ValueError):
            return None
    return None


def none_expr(value: object) -> z3.BoolRef | None:
    """Return the Z3 ``is_none`` predicate for a symbolic stack value."""
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(value, SymbolicValue):
        return value.is_none
    if isinstance(value, SymbolicObject):
        return value.is_none
    return None


def known_sequence_length(value: object) -> int | None:
    """Return a definite sequence length when it is concrete or a Z3 constant."""
    expression = length_expr(value)
    if expression is not None and z3.is_int_value(expression):
        return expression.as_long()
    return None


def has_retained_concrete_value(value: object) -> bool:
    """Return whether a value is concrete rather than an unresolved symbolic carrier."""
    if not isinstance(value, SymbolicType):
        return True
    from pysymex._internal.core.types.containers.bytes import SymbolicBytes
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.sets import SymbolicSet
    from pysymex._internal.core.types.containers.tuples import SymbolicTuple
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(value, SymbolicValue):
        return value.value is not None or (
            normalize_affinity(value.affinity_type) == AffinityKind.NONE
            and z3.is_true(value.is_none)
        )
    if isinstance(value, SymbolicString):
        return value.concrete_value is not None
    if isinstance(value, SymbolicBytes):
        return value.concrete_value is not None
    if isinstance(value, (SymbolicList, SymbolicDict, SymbolicSet)):
        return value.concrete_items is not None
    if isinstance(value, SymbolicTuple):
        return all(has_retained_concrete_value(item) for item in value.elements)
    if isinstance(value, SymbolicFloat):
        return z3.is_fp_value(value.z3_expr)
    return False


def symbolic_affinity(value: object) -> str:
    """Return the canonical coarse Python type represented by a value."""
    from pysymex._internal.core.types.base import SymbolicNoneType
    from pysymex._internal.core.types.containers.bytes import SymbolicBytes
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.sets import SymbolicSet
    from pysymex._internal.core.types.containers.tuples import SymbolicTuple
    from pysymex._internal.core.types.numeric.bool import SymbolicBool
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(value, SymbolicValue):
        return normalize_affinity(value.affinity_type)
    if isinstance(value, SymbolicNoneType) or value is None:
        return AffinityKind.NONE
    families = (
        (SymbolicBool, AffinityKind.BOOL),
        (SymbolicInt, AffinityKind.INT),
        (SymbolicFloat, AffinityKind.FLOAT),
        (SymbolicString, AffinityKind.STR),
        (SymbolicBytes, AffinityKind.BYTES),
        (SymbolicList, AffinityKind.LIST),
        (SymbolicDict, AffinityKind.DICT),
        (SymbolicTuple, AffinityKind.TUPLE),
        (SymbolicSet, AffinityKind.SET),
    )
    for carrier_type, affinity in families:
        if isinstance(value, carrier_type):
            return affinity
    if isinstance(value, bool):
        return AffinityKind.BOOL
    if isinstance(value, int):
        return AffinityKind.INT
    if isinstance(value, float):
        return AffinityKind.FLOAT
    if isinstance(value, str):
        return AffinityKind.STR
    if isinstance(value, bytes):
        return AffinityKind.BYTES
    if isinstance(value, bytearray):
        return AffinityKind.BYTEARRAY
    if isinstance(value, list):
        return AffinityKind.LIST
    if isinstance(value, dict):
        return AffinityKind.DICT
    if isinstance(value, tuple):
        return AffinityKind.TUPLE
    if isinstance(value, set):
        return AffinityKind.SET
    if isinstance(value, frozenset):
        return AffinityKind.FROZENSET
    return AffinityKind.UNKNOWN
