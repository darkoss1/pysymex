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

"""Symbolic coercion helpers for modeled scalar conversions."""

from __future__ import annotations

import z3

from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val, get_real_val
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.numeric.bool import SymbolicBool
from pysymex.core.types.numeric.float import SymbolicFloat
from pysymex.core.types.numeric.int import SymbolicInt
from pysymex.core.types.scalars.strings import SymbolicString


def coerce_to_bool(value: SymbolicType) -> SymbolicBool:
    """Return a symbolic boolean built from the value's truthiness expression."""
    if isinstance(value, SymbolicBool):
        return value
    return SymbolicBool(value.is_truthy())


def coerce_to_int(value: SymbolicType) -> SymbolicInt:
    """Return an integer representation or a fresh unconstrained integer fallback.

    Limitations:
        Values other than modeled integers, booleans, and floats are replaced
        with a fresh symbolic integer rather than constrained Python ``int()``
        conversion semantics.
    """
    match value:
        case SymbolicInt():
            return value
        case SymbolicBool():
            return SymbolicInt(z3.If(value.z3_bool, get_int_val(1), Z3_ZERO))
        case SymbolicFloat():
            return value.to_int()
        case _:
            return SymbolicInt.symbolic(f"int_{value.name}")


def coerce_to_float(value: SymbolicType) -> SymbolicFloat:
    """Return a float representation or a fresh unconstrained float fallback.

    Limitations:
        Values other than modeled floats, integers, and booleans are replaced
        with a fresh symbolic float rather than constrained Python conversion.
    """
    match value:
        case SymbolicFloat():
            return value
        case SymbolicInt():
            return SymbolicFloat(z3.ToReal(value.z3_int))
        case SymbolicBool():
            return SymbolicFloat(z3.If(value.z3_bool, get_real_val(1), get_real_val(0)))
        case _:
            return SymbolicFloat.symbolic(f"float_{value.name}")


def coerce_to_string(value: SymbolicType) -> SymbolicString:
    """Return a string representation or a fresh unconstrained string fallback.

    Limitations:
        Only symbolic strings and integers have an encoded conversion here;
        other inputs produce a fresh symbolic string.
    """
    if isinstance(value, SymbolicString):
        return value
    elif isinstance(value, SymbolicInt):
        return SymbolicString(z3.IntToStr(value.z3_int))
    else:
        return SymbolicString.symbolic(f"str_{value.name}")[0]


__all__ = [
    "coerce_to_bool",
    "coerce_to_float",
    "coerce_to_int",
    "coerce_to_string",
]
