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

"""Exact input extraction for modeled iterator predicates."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType, SymbolicType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

ExactFilterValue = int | float | bool | str | bytes | bytearray | list[object] | tuple[object, ...]


def callable_payload(function: object) -> object:
    if isinstance(function, SymbolicValue):
        payload = getattr(function, "_modeled_object", None)
        if payload is not None:
            return payload
        value = function.value
        if isinstance(value, type):
            return value
    return function


def exact_filter_predicate_str_input(item: object) -> str | None:
    if item is None or isinstance(item, SymbolicNoneType):
        return "None"
    if isinstance(item, (str, bytes, bytearray, int, float, bool)):
        return str(item)
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        if item.value is None and z3.is_true(simplify_expr(item.is_none)):
            return "None"
        if isinstance(item.value, (str, bytes, bytearray, int, float, bool)):
            return str(item.value)
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
        simplified_int = simplify_expr(item.z3_int)
        if z3.is_int_value(simplified_int):
            return str(simplified_int.as_long())
    return None


def exact_filter_predicate_input(item: object) -> ExactFilterValue | None:
    if isinstance(item, (int, float, bool, str, bytes, bytearray)):
        return item
    if isinstance(item, SymbolicBytes):
        return item.concrete_value
    list_value = _exact_list_value(item)
    if list_value is not None:
        return list_value
    tuple_value = _exact_tuple_value(item)
    if tuple_value is not None:
        return tuple_value
    if isinstance(item, SymbolicList):
        bytearray_value = _exact_symbolic_bytearray_value(item)
        if bytearray_value is not None:
            return bytearray_value
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        modeled_object = getattr(item, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicList):
            modeled_bytearray = _exact_symbolic_bytearray_value(modeled_object)
            if modeled_bytearray is not None:
                return modeled_bytearray
        modeled_list = _exact_list_value(modeled_object)
        if modeled_list is not None:
            return modeled_list
        modeled_tuple = _exact_tuple_value(modeled_object)
        if modeled_tuple is not None:
            return modeled_tuple
        if isinstance(item.value, (int, float, bool, str, bytes, bytearray)):
            return item.value
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
        simplified_int = simplify_expr(item.z3_int)
        if z3.is_int_value(simplified_int):
            return simplified_int.as_long()
    return None


def _exact_list_value(item: object) -> list[object] | None:
    raw_items: list[object]
    if isinstance(item, SymbolicList):
        if getattr(item, "_type", None) == "bytearray" or item.concrete_items is None:
            return None
        raw_items = item.concrete_items
    elif isinstance(item, list):
        raw_items = cast("list[object]", item)
    else:
        return None

    exact_items: list[object] = []
    for raw_item in raw_items:
        exact_item = exact_filter_predicate_input(raw_item)
        if exact_item is None:
            return None
        exact_items.append(exact_item)
    return exact_items


def _exact_tuple_value(item: object) -> tuple[object, ...] | None:
    raw_items: tuple[object, ...]
    if isinstance(item, SymbolicTuple):
        raw_items = item.elements
    elif isinstance(item, tuple):
        raw_items = cast("tuple[object, ...]", item)
    else:
        return None

    exact_items: list[object] = []
    for raw_item in raw_items:
        exact_item = exact_filter_predicate_input(raw_item)
        if exact_item is None:
            return None
        exact_items.append(exact_item)
    return tuple(exact_items)


def _exact_symbolic_bytearray_value(item: SymbolicList) -> bytearray | None:
    if getattr(item, "_type", None) != "bytearray" or item.concrete_items is None:
        return None
    values: list[int] = []
    for concrete_item in item.concrete_items:
        byte_value = _exact_bytearray_item(concrete_item)
        if byte_value is None:
            return None
        values.append(byte_value)
    return bytearray(values)


def _exact_bytearray_item(item: object) -> int | None:
    if isinstance(item, SymbolicValue):
        item = item.value
    if isinstance(item, bool):
        return int(item)
    if isinstance(item, int) and 0 <= item <= 255:
        return item
    return None


def exact_int_map_input(item: object) -> str | bytes | bytearray | int | bool | float | None:
    if isinstance(item, (str, bytes, bytearray, int, bool, float)):
        return item
    if isinstance(item, SymbolicString):
        if not z3.is_string_value(item.z3_str):
            return None
        try:
            return item.z3_str.as_string()
        except z3.Z3Exception:
            return None
    if isinstance(item, SymbolicValue):
        if isinstance(item.value, (str, bytes, bytearray, int, bool, float)):
            return item.value
        if z3.is_true(item.is_str) and z3.is_string_value(item.z3_str):
            try:
                return item.z3_str.as_string()
            except z3.Z3Exception:
                return None
    return None


def truth_predicate(value: object) -> z3.BoolRef | None:
    if isinstance(value, SymbolicValue):
        return value.could_be_truthy()
    if isinstance(value, SymbolicType):
        return value.could_be_truthy()
    if isinstance(value, (bool, int, float, str, bytes, bytearray)):
        return Z3_TRUE if value else Z3_FALSE
    if isinstance(value, list):
        return Z3_TRUE if cast("list[object]", value) else Z3_FALSE
    if isinstance(value, tuple):
        return Z3_TRUE if cast("tuple[object, ...]", value) else Z3_FALSE
    if isinstance(value, dict):
        return Z3_TRUE if cast("dict[object, object]", value) else Z3_FALSE
    if isinstance(value, (set, frozenset)):
        return Z3_TRUE if cast("set[object] | frozenset[object]", value) else Z3_FALSE
    return None


def exact_constant_truth_value(value: object) -> bool | None:
    if value is None or isinstance(value, SymbolicNoneType):
        return False
    if isinstance(value, (bool, int, float, str, bytes, bytearray)):
        return bool(value)
    if isinstance(value, tuple):
        return bool(cast("tuple[object, ...]", value))
    if isinstance(value, frozenset):
        return bool(cast("frozenset[object]", value))
    return None
