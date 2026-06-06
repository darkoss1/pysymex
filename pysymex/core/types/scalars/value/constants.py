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

"""Concrete value conversion for scalar symbolic values."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from pysymex.guards import is_dict_of_objects
from pysymex.core.constants import (
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex.core.solver.constraints.hashing import get_float64_val
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.scalars.value import helpers as _scalar_value_helpers
from pysymex.core.types.scalars.value.helpers import is_list_of_objects

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor

if TYPE_CHECKING:
    from pysymex.core.types.scalars.strings import SymbolicString as _SymbolicStringType
    from pysymex.core.types.scalars.values import SymbolicValue as _SymbolicValueType
else:
    _SymbolicStringType = object
    _SymbolicValueType = object

SymbolicValue = cast(SymbolicValueConstructor, object)
SymbolicString = cast("type[_SymbolicStringType]", object)
FROM_CONST_CACHE = cast(
    "dict[str | tuple[str, int] | tuple[str, float], _SymbolicValueType]",
    _scalar_value_helpers.FROM_CONST_CACHE,
)
FROM_CONST_CACHE_LIMIT = _scalar_value_helpers.FROM_CONST_CACHE_LIMIT
FROM_CONST_CACHE_LOCK = _scalar_value_helpers.FROM_CONST_CACHE_LOCK
cached_int_value_is_usable = cast(
    "Callable[[_SymbolicValueType], bool]",
    _scalar_value_helpers.cached_int_value_is_usable,
)


def bind_symbolic_value_classes(
    value_cls: SymbolicValueConstructor, string_cls: type[object]
) -> None:
    """Bind carrier classes used by concrete-value conversion."""
    global SymbolicValue, SymbolicString
    SymbolicValue = value_cls
    SymbolicString = string_cls


class SymbolicValueConstantMixin:
    """Create unified scalar carriers from concrete Python objects."""

    @staticmethod
    def from_const(value: object) -> _SymbolicValueType:
        """Create a carrier for a concrete Python value.

        Notes:
            ``None``, booleans, integers, and floats may reuse bounded cache
            entries. Lists and dictionaries retain their concrete modeled
            objects and expose lengths through the integer channel.

        Limitations:
            Other arbitrary objects are retained as modeled payloads without
            introducing object-type predicates or symbolic behavior here.
        """
        from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

        symbolic_value_type = cast("type[_SymbolicValueType]", SymbolicValue)
        if isinstance(value, symbolic_value_type):
            return value
        if isinstance(value, AdvancedSymbolicFloat):
            return SymbolicValue(
                _name=value.name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=value.z3_expr,
                is_float=Z3_TRUE,
                is_path=Z3_FALSE,
                affinity_type="float",
            )
        if value is None:
            cached = FROM_CONST_CACHE.get("None")
            if cached is not None:
                return cached
            sv = SymbolicValue(
                _name="None",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_TRUE,
                affinity_type="NoneType",
                _h_active=False,
            )
            with FROM_CONST_CACHE_LOCK:
                FROM_CONST_CACHE["None"] = sv
            return sv
        if isinstance(value, bool):
            key = "True" if value else "False"
            cached = FROM_CONST_CACHE.get(key)
            if cached is not None and cached_int_value_is_usable(cached):
                return cached
            if cached is not None:
                FROM_CONST_CACHE.pop(key, None)

            if value:
                sv = SymbolicValue(
                    _name="True",
                    z3_int=Z3_ONE,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_TRUE,
                    is_bool=Z3_TRUE,
                    is_path=Z3_FALSE,
                    _constant_value=True,
                    affinity_type="bool",
                    min_val=1,
                    max_val=1,
                )
            else:
                sv = SymbolicValue(
                    _name="False",
                    z3_int=Z3_ZERO,
                    is_int=Z3_FALSE,
                    z3_bool=Z3_FALSE,
                    is_bool=Z3_TRUE,
                    is_path=Z3_FALSE,
                    _constant_value=False,
                    affinity_type="bool",
                    min_val=0,
                    max_val=0,
                )

            with FROM_CONST_CACHE_LOCK:
                FROM_CONST_CACHE[key] = sv
            return sv
        if isinstance(value, int):
            key = ("int", value)
            cached = FROM_CONST_CACHE.get(key)
            if cached is not None and cached_int_value_is_usable(cached):
                return cached
            if cached is not None:
                FROM_CONST_CACHE.pop(key, None)
            sv = SymbolicValue(
                _name=str(value),
                z3_int=get_int_val(value),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=get_float64_val(float(value)),
                is_float=Z3_FALSE,
                is_path=Z3_FALSE,
                _constant_value=value,
                affinity_type="int",
                min_val=value,
                max_val=value,
            )

            with FROM_CONST_CACHE_LOCK:
                if len(FROM_CONST_CACHE) < FROM_CONST_CACHE_LIMIT:
                    FROM_CONST_CACHE[key] = sv
            return sv

        if isinstance(value, float):
            key = ("float", value)
            cached = FROM_CONST_CACHE.get(key)
            if cached is not None:
                return cached
            try:
                int_val = int(value)
                z3_int = get_int_val(int_val)
            except (ValueError, OverflowError):
                z3_int = Z3_ZERO

            sv = SymbolicValue(
                _name=str(value),
                z3_int=z3_int,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=get_float64_val(value),
                is_float=Z3_TRUE,
                is_path=Z3_FALSE,
                _constant_value=value,
                affinity_type="float",
                min_val=value,
                max_val=value,
            )
            with FROM_CONST_CACHE_LOCK:
                if len(FROM_CONST_CACHE) < FROM_CONST_CACHE_LIMIT:
                    FROM_CONST_CACHE[key] = sv
            return sv

        if hasattr(value, "type_tag"):
            return SymbolicValue.from_specialized(value)

        if isinstance(value, str):
            from pysymex.core.types.scalars.strings import SymbolicString

            return SymbolicValue.from_specialized(SymbolicString.from_const(value))

        sv = SymbolicValue(
            _name=str(value),
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            _constant_value=value,
        )
        if is_list_of_objects(value):
            sv.is_list = Z3_TRUE
            sv.affinity_type = "list"
            sv.z3_int = get_int_val(len(value))
            setattr(sv, "_modeled_object", value)
            setattr(sv, "_constant_value", value)
        elif is_dict_of_objects(value):
            sv.is_dict = Z3_TRUE
            sv.affinity_type = "dict"
            sv.z3_int = get_int_val(len(value))
            setattr(sv, "_modeled_object", value)
            setattr(sv, "_constant_value", value)
        elif isinstance(value, tuple):
            setattr(sv, "_modeled_object", value)
            setattr(sv, "_constant_value", value)
        elif isinstance(value, set):
            setattr(sv, "_modeled_object", value)
            setattr(sv, "_constant_value", value)
        else:
            setattr(sv, "_modeled_object", value)
        return sv
