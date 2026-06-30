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

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import (
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.affinity import AffinityKind
from pysymex._internal.core.types.capabilities import length_expr
from pysymex._internal.core.types.scalars.value.protocols import (
    ValueConstructor,
    unbound_symbolic_value_constructor,
)

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue

_symbolic_value_cls = unbound_symbolic_value_constructor()
_symbolic_string_cls: type[object] = object


def bind_symbolic_value_specializations(
    value_cls: ValueConstructor,
    string_cls: type[object],
) -> None:
    """Bind carrier classes used to lift specialized symbolic values."""
    global _symbolic_value_cls, _symbolic_string_cls
    _symbolic_value_cls = value_cls
    _symbolic_string_cls = string_cls


def _specialized_name(value: object) -> str:
    """Return the stable diagnostic name for a specialized symbolic value."""
    return getattr(value, "name", str(value))


def _from_specialized_scalar(value: object, name: str) -> SymbolicValue | None:
    """Convert scalar specialized carriers into the unified value channel set."""
    from pysymex._internal.core.types.base import SymbolicNoneType
    from pysymex._internal.core.types.numeric.bool import SymbolicBool
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt
    from pysymex._internal.core.types.scalars.strings import SymbolicString

    if isinstance(value, SymbolicNoneType):
        return _symbolic_value_cls(
            _name=name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_none=Z3_TRUE,
            is_path=Z3_FALSE,
            _h_active=getattr(value, "_h_active", False),
            affinity_type=AffinityKind.NONE,
        )
    if isinstance(value, SymbolicBool):
        return _symbolic_value_cls(
            _name=name,
            z3_int=z3.If(value.z3_bool, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=value.z3_bool,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.BOOL,
        )
    if isinstance(value, SymbolicInt):
        return _symbolic_value_cls(
            _name=name,
            z3_int=value.z3_int,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.INT,
        )
    if isinstance(value, SymbolicFloat):
        int_value = value.to_int()
        return _symbolic_value_cls(
            _name=name,
            z3_int=int_value.z3_int,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=value.z3_expr,
            is_float=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.FLOAT,
        )
    if isinstance(value, SymbolicString):
        return _symbolic_value_cls(
            _name=name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_str=value.z3_str,
            is_str=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.STR,
        )
    return None


def _symbolic_list_length(value: object) -> z3.ArithRef:
    """Return the best available length channel for a symbolic list-like object."""
    expr = length_expr(value)
    return expr if expr is not None else Z3_ZERO


def _symbolic_dict_length(value: object) -> z3.ArithRef:
    """Return the best available length channel for a symbolic dict-like object."""
    expr = length_expr(value)
    return expr if expr is not None else Z3_ZERO


def _from_specialized_container(value: object, name: str) -> SymbolicValue | None:
    """Convert container/object specialized carriers into unified channels."""
    from pysymex._internal.core.types.containers.bytes import SymbolicBytes
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.core.types.containers.sets import SymbolicSet
    from pysymex._internal.core.types.containers.tuples import SymbolicTuple

    if isinstance(value, SymbolicList):
        return _symbolic_value_cls(
            _name=name,
            z3_int=_symbolic_list_length(value),
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_array=getattr(value, "z3_array", None),
            is_list=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.LIST,
        )
    if isinstance(value, SymbolicDict):
        return _symbolic_value_cls(
            _name=name,
            z3_int=_symbolic_dict_length(value),
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_array=getattr(value, "z3_array", None),
            is_dict=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.DICT,
        )
    if isinstance(value, SymbolicObject):
        return _symbolic_value_cls(
            _name=name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=value.z3_addr,
            is_obj=Z3_TRUE,
            is_path=Z3_FALSE,
            _h_active=getattr(value, "_h_active", False),
            affinity_type=AffinityKind.OBJECT,
        )
    if isinstance(value, SymbolicBytes):
        return _symbolic_value_cls(
            _name=name,
            z3_int=value.z3_len,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_bytes=value.z3_bytes,
            is_bytes=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.BYTES,
        )
    if isinstance(value, SymbolicTuple):
        return _symbolic_value_cls(
            _name=name,
            z3_int=ConstraintValues.int(len(value)),
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_tuple=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.TUPLE,
            _constant_value=value.elements,
        )
    if isinstance(value, SymbolicSet):
        return _symbolic_value_cls(
            _name=name,
            z3_int=value.length.z3_int,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_set=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type=AffinityKind.SET,
            _constant_value=value.concrete_items,
        )
    return None


class ValueSpecializationMixin:
    """Convert specialized symbolic values into unified scalar channels."""

    @staticmethod
    def from_specialized(value: object) -> SymbolicValue:
        """Map recognized specialized values into available unified channels.

        Limitations:
            Real-sort floats are converted into Float64 FP payloads. Known bytes,
            tuple, and set carriers retain their type channels.
        """
        from pysymex._internal.core.types.scalars.values import SymbolicValue as _SV

        if isinstance(value, _SV):
            return value

        name = _specialized_name(value)
        for converter in (
            _from_specialized_scalar,
            _from_specialized_container,
        ):
            converted = converter(value, name)
            if converted is not None:
                return converted
        return _symbolic_value_cls.from_const(value)
