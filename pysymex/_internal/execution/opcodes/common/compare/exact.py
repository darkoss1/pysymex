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

"""Exact retained-value equality helpers for comparison-family opcodes."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.numeric.bool import SymbolicBool
from pysymex._internal.core.types.numeric.int import SymbolicInt
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

_UNKNOWN_COMPARISON_VALUE = object()


def exact_concrete_equal(left: object, right: object) -> bool | None:
    """Return exact equality when retained symbolic payloads can be unwrapped."""
    same_symbolic = _same_definite_symbolic_scalar_equal(left, right)
    if same_symbolic is not None:
        return same_symbolic

    left_tuple = _exact_tuple_items(left)
    right_tuple = _exact_tuple_items(right)
    if left_tuple is not None and right_tuple is not None:
        if len(left_tuple) != len(right_tuple):
            return False
        saw_unknown = False
        for left_item, right_item in zip(left_tuple, right_tuple, strict=True):
            equal = exact_concrete_equal(left_item, right_item)
            if equal is False:
                return False
            if equal is None:
                saw_unknown = True
        return None if saw_unknown else True

    left_value = _exact_concrete_payload(left)
    right_value = _exact_concrete_payload(right)
    if left_value is _UNKNOWN_COMPARISON_VALUE or right_value is _UNKNOWN_COMPARISON_VALUE:
        return None
    if isinstance(left_value, tuple) and isinstance(right_value, tuple):
        left_tuple = cast("tuple[object, ...]", left_value)
        right_tuple = cast("tuple[object, ...]", right_value)
        if len(left_tuple) != len(right_tuple):
            return False
        saw_unknown = False
        for left_item, right_item in zip(left_tuple, right_tuple, strict=True):
            equal = exact_concrete_equal(left_item, right_item)
            if equal is False:
                return False
            if equal is None:
                saw_unknown = True
        return None if saw_unknown else True
    return _exact_bool_or_none(left_value == right_value)


def exact_equality_condition(left: object, right: object, op_name: str) -> z3.BoolRef | None:
    """Return exact retained ``==`` or ``!=`` condition when both operands are decidable."""
    if op_name not in {"==", "!="}:
        return None
    equal = exact_concrete_equal(left, right)
    if equal is None:
        return None
    if op_name == "!=":
        equal = not equal
    return Z3_TRUE if equal else Z3_FALSE


def exact_bool_identity_condition(left: object, right: object) -> z3.BoolRef | None:
    """Return exact bool identity condition for retained concrete bool payloads."""
    left_value = _exact_concrete_payload(left)
    right_value = _exact_concrete_payload(right)
    if left_value is _UNKNOWN_COMPARISON_VALUE or right_value is _UNKNOWN_COMPARISON_VALUE:
        return None
    if not isinstance(left_value, bool) and not isinstance(right_value, bool):
        return None
    return Z3_TRUE if left_value is right_value else Z3_FALSE


def _same_definite_symbolic_scalar_equal(left: object, right: object) -> bool | None:
    """Return ``True`` for the same retained symbolic scalar when reflexivity is sound."""
    if left is not right:
        return None
    if isinstance(left, SymbolicValue):
        if (
            z3.is_true(simplify_expr(left.is_int))
            or z3.is_true(simplify_expr(left.is_bool))
            or z3.is_true(simplify_expr(left.is_str))
            or z3.is_true(simplify_expr(left.is_none))
        ):
            return True
        return None
    if isinstance(left, (SymbolicInt, SymbolicBool, SymbolicString, SymbolicBytes)):
        return True
    return None


def _exact_bool_or_none(value: object) -> bool | None:
    """Return a concrete bool only when an equality result is fully decided."""
    if isinstance(value, bool):
        return value
    if isinstance(value, z3.BoolRef):
        simplified = simplify_expr(value)
        if z3.is_true(simplified):
            return True
        if z3.is_false(simplified):
            return False
    return None


def _exact_concrete_payload(value: object) -> object:
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return value.value
        if z3.is_true(simplify_expr(value.is_none)):
            return None
        if z3.is_true(simplify_expr(value.is_str)) and z3.is_string_value(value.z3_str):
            try:
                return value.z3_str.as_string()
            except z3.Z3Exception:
                return _UNKNOWN_COMPARISON_VALUE
        return _UNKNOWN_COMPARISON_VALUE
    if isinstance(value, SymbolicInt):
        simplified = simplify_expr(value.z3_int)
        if z3.is_int_value(simplified):
            return simplified.as_long()
        return _UNKNOWN_COMPARISON_VALUE
    if isinstance(value, SymbolicBool):
        simplified = simplify_expr(value.z3_bool)
        if z3.is_true(simplified):
            return True
        if z3.is_false(simplified):
            return False
        return _UNKNOWN_COMPARISON_VALUE
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return _UNKNOWN_COMPARISON_VALUE
    if isinstance(value, SymbolicBytes):
        return (
            value.concrete_value if value.concrete_value is not None else _UNKNOWN_COMPARISON_VALUE
        )
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) in {"bytes", "bytearray"}:
        concrete_items = value.concrete_items
        if concrete_items is None:
            return _UNKNOWN_COMPARISON_VALUE
        byte_values = _exact_byte_values(concrete_items)
        if byte_values is None:
            return _UNKNOWN_COMPARISON_VALUE
        if getattr(value, "_type", None) == "bytearray":
            return bytearray(byte_values)
        return bytes(byte_values)
    if isinstance(value, SymbolicTuple):
        return tuple(_exact_concrete_payload(item) for item in value.elements)
    if isinstance(value, tuple):
        items = cast("tuple[object, ...]", value)
        return tuple(_exact_concrete_payload(item) for item in items)
    return value


def _exact_byte_values(items: list[object]) -> list[int] | None:
    byte_values: list[int] = []
    for item in items:
        value = _exact_concrete_payload(item)
        if isinstance(value, bool):
            value = int(value)
        if not isinstance(value, int) or not 0 <= value <= 255:
            return None
        byte_values.append(value)
    return byte_values


def _exact_tuple_items(value: object) -> tuple[object, ...] | None:
    """Return retained tuple elements before symbolic payload normalization."""
    if isinstance(value, SymbolicTuple):
        return tuple(value.elements)
    if isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple":
        concrete_items = value.concrete_items
        return None if concrete_items is None else tuple(concrete_items)
    if isinstance(value, tuple):
        return cast("tuple[object, ...]", value)
    if isinstance(value, SymbolicValue):
        constant_value = value.value
        if isinstance(constant_value, tuple):
            return cast("tuple[object, ...]", constant_value)
    return None
