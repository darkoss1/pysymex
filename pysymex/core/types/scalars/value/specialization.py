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

"""Specialized symbolic type conversion for scalar symbolic values."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.constants import (
    Z3_EMPTY_STRING,
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex.core.solver.constraints.hashing import get_int_val

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor

if TYPE_CHECKING:
    from pysymex.core.types.scalars.strings import SymbolicString as _SymbolicStringType
    from pysymex.core.types.scalars.values import SymbolicValue as _SymbolicValueType
else:
    _SymbolicStringType = object
    _SymbolicValueType = object

SymbolicValue = cast(SymbolicValueConstructor, object)
SymbolicString = cast("type[_SymbolicStringType]", object)


def bind_symbolic_value_classes(
    value_cls: SymbolicValueConstructor, string_cls: type[object]
) -> None:
    """Bind carrier classes used to lift specialized symbolic values."""
    global SymbolicValue, SymbolicString
    SymbolicValue = value_cls
    SymbolicString = string_cls


class SymbolicValueSpecializationMixin:
    """Convert specialized symbolic values into unified scalar channels."""

    @staticmethod
    def from_specialized(value: object) -> _SymbolicValueType:
        """Map recognized specialized values into available unified channels.

        Limitations:
            Real-sort floats are converted into Float64 FP payloads. Bytes,
            tuples, sets, and unrecognized symbolic types currently become
            unknown-affinity carriers without preserving their specialized
            payload semantics.
        """
        from pysymex.core.types.numeric.bool import SymbolicBool
        from pysymex.core.types.numeric.int import SymbolicInt
        from pysymex.core.types.numeric.float import SymbolicFloat
        from pysymex.core.types.containers.dicts import SymbolicDict
        from pysymex.core.types.containers.lists import SymbolicList
        from pysymex.core.types.containers.objects import SymbolicObject
        from pysymex.core.types.scalars.strings import SymbolicString
        from pysymex.core.types.containers.bytes import SymbolicBytes
        from pysymex.core.types.containers.sequences import SymbolicTuple
        from pysymex.core.types.containers.sequences import SymbolicSet
        from pysymex.core.types.base import SymbolicNoneType

        symbolic_value_type = cast("type[_SymbolicValueType]", SymbolicValue)
        if isinstance(value, symbolic_value_type):
            return value

        name = getattr(value, "name", str(value))

        if isinstance(value, SymbolicNoneType):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_none=Z3_TRUE,
                is_path=Z3_FALSE,
                _h_active=getattr(value, "_h_active", False),
                affinity_type="none",
            )
        if isinstance(value, SymbolicBool):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(value.z3_bool, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=value.z3_bool,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="bool",
            )
        if isinstance(value, SymbolicInt):
            return SymbolicValue(
                _name=name,
                z3_int=value.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="int",
            )
        if isinstance(value, SymbolicFloat):
            _abs_floor = z3.ToInt(z3.If(value.z3_real >= 0, value.z3_real, -value.z3_real))
            _sign = z3.If(value.z3_real < 0, get_int_val(-1), Z3_ONE)
            return SymbolicValue(
                _name=name,
                z3_int=_abs_floor * _sign,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=z3.fpToFP(z3.RNE(), value.z3_real, z3.Float64()),
                is_float=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="float",
            )
        if isinstance(value, SymbolicString):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_str=value.z3_str,
                is_str=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="str",
            )
        if isinstance(value, SymbolicList):
            z3_len = getattr(value, "z3_len", None)
            if z3_len is None and hasattr(value, "z3_seq"):
                z3_len = z3.Length(getattr(value, "z3_seq"))
            if z3_len is None:
                z3_len = Z3_ZERO
            return SymbolicValue(
                _name=name,
                z3_int=z3_len,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_array=getattr(value, "z3_array", None),
                is_list=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="list",
            )
        if isinstance(value, SymbolicDict):
            z3_len = getattr(value, "z3_len", None)
            if z3_len is None and hasattr(value, "length"):
                len_obj = getattr(value, "length")
                z3_len = (
                    getattr(len_obj, "z3_int", Z3_ZERO)
                    if not isinstance(len_obj, (int, float))
                    else get_int_val(int(len_obj))
                )
            if z3_len is None:
                z3_len = Z3_ZERO
            return SymbolicValue(
                _name=name,
                z3_int=z3_len,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_array=getattr(value, "z3_array", None),
                is_dict=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="dict",
            )
        if isinstance(value, SymbolicObject):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_addr=value.z3_addr,
                is_obj=Z3_TRUE,
                is_path=Z3_FALSE,
                _h_active=getattr(value, "_h_active", False),
                affinity_type="obj",
            )
        if isinstance(value, (SymbolicBytes, SymbolicTuple, SymbolicSet)):
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="unknown",
            )

        if hasattr(value, "type_tag"):
            cls_name = type(value).__name__
            if cls_name == "SymbolicString":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_str=getattr(value, "z3_str", Z3_EMPTY_STRING),
                    is_str=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="str",
                )
            if cls_name == "SymbolicList":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_array=getattr(value, "z3_array", None),
                    is_list=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="list",
                )
            if cls_name == "SymbolicDict":
                return SymbolicValue(
                    _name=name,
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_FALSE,
                    z3_array=getattr(value, "z3_array", None),
                    is_dict=Z3_TRUE,
                    is_path=Z3_FALSE,
                    affinity_type="dict",
                )

            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                affinity_type="unknown",
            )

        return SymbolicValue.from_const(value)
