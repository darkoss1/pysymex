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

"""Symbolic construction helpers for Python values and type hints."""

from __future__ import annotations

from typing import TypeGuard, cast

from pysymex.core.types.base import SYMBOLIC_NONE, fresh_name
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicSet, SymbolicTuple
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.float import SymbolicFloat
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.scalars.strings import SymbolicString


def _is_int_list(values: list[object]) -> TypeGuard[list[int]]:
    """Return whether every list element is a concrete integer."""
    return all(isinstance(value, int) for value in values)


def _is_int_set(values: set[object]) -> TypeGuard[set[int]]:
    """Return whether every set element is a concrete integer."""
    return all(isinstance(value, int) for value in values)


def symbolic_from_python(value: object) -> object:
    """Map supported Python constants to symbolic representations.

    Limitations:
        Non-integer lists and sets are widened to symbolic integer
        collections. Values with no explicit case become fresh symbolic
        integers, so this helper does not preserve arbitrary Python objects.
    """
    if value is None:
        return SYMBOLIC_NONE
    if isinstance(value, bool):
        return SymbolicBool.concrete(value)
    if isinstance(value, int):
        return SymbolicInt.concrete(value)
    if isinstance(value, float):
        return SymbolicFloat.concrete(value)
    if isinstance(value, str):
        return SymbolicString.from_const(value)
    if isinstance(value, bytes):
        return SymbolicBytes.concrete(value)
    if isinstance(value, tuple):
        tuple_values = cast("tuple[object, ...]", value)
        elements = tuple(symbolic_from_python(element) for element in tuple_values)
        return SymbolicTuple(elements)
    if isinstance(value, list):
        list_values = list(cast("list[object]", value))
        if not list_values:
            return SymbolicList.concrete_int_list([])
        if _is_int_list(list_values):
            return SymbolicList.concrete_int_list(list_values)
        return SymbolicList.symbolic_int_list()
    if isinstance(value, dict):
        dict_values = dict(cast("dict[object, object]", value))
        return SymbolicDict.from_const(dict_values)
    if isinstance(value, set):
        set_values = set(cast("set[object]", value))
        if _is_int_set(set_values):
            return SymbolicSet.from_const(set_values)
        return SymbolicSet.symbolic_int_set()
    return SymbolicInt.symbolic(f"unknown_{type(value).__name__}")


def symbolic_for_type(type_hint: type, name: str | None = None) -> object:
    """Create a symbolic representative for a recognized Python type hint.

    Limitations:
        Unrecognized type hints currently receive a symbolic integer rather
        than an object-specific model.
    """
    match type_hint:
        case t if t is type(None):
            return SYMBOLIC_NONE
        case t if t is bool:
            return SymbolicBool.symbolic(name)
        case t if t is int:
            return SymbolicInt.symbolic(name)
        case t if t is float:
            return SymbolicFloat.symbolic(name)
        case t if t is str:
            return SymbolicString.symbolic(name or fresh_name("str"))[0]
        case t if t is bytes:
            return SymbolicBytes.symbolic(name)
        case t if t is list:
            return SymbolicList.symbolic_int_list(name)
        case t if t is dict:
            return SymbolicDict.symbolic_int_dict(name)
        case t if t is set:
            return SymbolicSet.symbolic_int_set(name)
        case _:
            return SymbolicInt.symbolic(name)


__all__ = ["symbolic_for_type", "symbolic_from_python"]
