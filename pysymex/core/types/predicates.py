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

"""Symbolic type predicates and common-type promotion helpers."""

from __future__ import annotations

from pysymex.core.types.base import SymbolicType, TypeTag
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicSet, SymbolicTuple
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.float import SymbolicFloat
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.scalars.strings import SymbolicString


def is_numeric(value: SymbolicType) -> bool:
    """Check if value is numeric (int or float)."""
    return isinstance(value, (SymbolicInt, SymbolicFloat))


def is_sequence(value: SymbolicType) -> bool:
    """Check if value is a sequence type."""
    return isinstance(value, (SymbolicString, SymbolicBytes, SymbolicTuple, SymbolicList))


def is_collection(value: SymbolicType) -> bool:
    """Check if value is any collection type."""
    return isinstance(value, (SymbolicTuple, SymbolicList, SymbolicDict, SymbolicSet))


def get_common_type(a: SymbolicType, b: SymbolicType) -> TypeTag:
    """Return numeric promotion tag using float, then int, then bool precedence."""
    if isinstance(a, SymbolicFloat) or isinstance(b, SymbolicFloat):
        return TypeTag.FLOAT
    if isinstance(a, SymbolicInt) or isinstance(b, SymbolicInt):
        return TypeTag.INT
    if isinstance(a, SymbolicBool) and isinstance(b, SymbolicBool):
        return TypeTag.BOOL
    return TypeTag.UNKNOWN


__all__ = ["get_common_type", "is_collection", "is_numeric", "is_sequence"]
