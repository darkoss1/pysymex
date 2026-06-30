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

"""Core bytes-search operand and slice argument semantics."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def concrete_bytes_search_literal(value: object) -> bytes | None:
    """Return a retained concrete bytes-like payload when available."""
    if isinstance(value, SymbolicBytes):
        return value.concrete_value
    return SymbolicList.concrete_bytes_literal(value)


def bytes_type_name_if_definitely_not_bytes_like(value: object) -> str | None:
    """Return a type name when ``value`` is definitely not bytes-like."""
    if concrete_bytes_search_literal(value) is not None:
        return None
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if concrete is not None:
            return type(concrete).__name__
        if z3.is_true(value.is_none):
            return "NoneType"
        if z3.is_true(value.is_bool):
            return "bool"
        if z3.is_true(value.is_int):
            return "int"
        if z3.is_true(value.is_str):
            return "str"
        if z3.is_true(value.is_bytes):
            return None
        return None
    if isinstance(value, SymbolicString):
        return "str"
    if isinstance(value, SymbolicNoneType) or value is None:
        return "NoneType"
    return type(value).__name__


def bytes_slice_bounds_are_definitely_invalid(values: Iterable[object]) -> bool:
    """Return whether any bytes slice bound is definitely invalid."""
    return any(bytes_slice_bound_is_definitely_invalid(value) for value in values)


def bytes_slice_bound_is_definitely_invalid(value: object) -> bool:
    """Return whether a bytes slice bound is definitely not int-like or ``None``."""
    if isinstance(value, SymbolicValue):
        if z3.is_true(value.is_none):
            return False
        if value.value is None:
            return False
        value = value.value
    if isinstance(value, SymbolicNoneType) or value is None:
        return False
    return not isinstance(value, bool | int)


def concrete_bytes_slice_args(args: Iterable[object]) -> list[int | None] | None:
    """Return exact CPython bytes slice indexes, or ``None`` when not concrete."""
    slice_args: list[int | None] = []
    for value in args:
        supported, concrete_index = concrete_optional_bytes_index(value)
        if not supported:
            return None
        slice_args.append(concrete_index)
    return slice_args


def concrete_optional_bytes_index(value: object) -> tuple[bool, int | None]:
    """Return whether ``value`` is a concrete optional bytes index and its value."""
    if isinstance(value, SymbolicValue):
        if z3.is_true(value.is_none):
            return True, None
        if value.value is None:
            return False, None
        value = value.value
    if isinstance(value, SymbolicNoneType) or value is None:
        return True, None
    concrete = concrete_bytes_index(value)
    if concrete is None:
        return False, None
    return True, concrete


def concrete_bytes_index(value: object) -> int | None:
    """Return the exact CPython integer index value when available."""
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def bytes_index_type_name_if_definitely_invalid(value: object) -> str | None:
    """Return a type name when ``value`` is definitely not int-like."""
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if concrete is not None:
            value = concrete
        elif z3.is_true(value.is_none):
            return "NoneType"
        elif z3.is_true(value.is_bool) or z3.is_true(value.is_int):
            return None
        elif z3.is_true(value.is_float):
            return "float"
        elif z3.is_true(value.is_str):
            return "str"
        else:
            return None
    if isinstance(value, SymbolicString):
        return "str"
    if isinstance(value, SymbolicNoneType) or value is None:
        return "NoneType"
    if isinstance(value, bool | int):
        return None
    return type(value).__name__
