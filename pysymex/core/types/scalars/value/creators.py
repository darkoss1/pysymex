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

"""Fresh-symbol and Z3 conversion factories for scalar symbolic values."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.constants import (
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex.core.types.scalars.value.helpers import (
    exactly_one_bool,
    next_address,
)

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf

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
    """Bind carrier classes used by symbolic-value construction."""
    global SymbolicValue, SymbolicString
    SymbolicValue = value_cls
    SymbolicString = string_cls


class SymbolicValueCreatorMixin:
    """Create unified scalar carriers and their required type constraints."""

    def as_string(self: SymbolicValueSelf) -> _SymbolicStringType:
        """Return a string view that delegates storage and truthiness to this value."""
        from pysymex.core.types.scalars.strings import SymbolicString

        return SymbolicString(
            _z3_str=self.z3_str,
            _z3_len=z3.Length(self.z3_str),
            _name=self.name,
            _unified=cast("_SymbolicValueType", self),
        )

    @staticmethod
    def symbolic(name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create an unconstrained carrier plus an exactly-one-type constraint.

        Notes:
            Callers must add the returned constraint before relying on a
            single active type discriminator.
        """
        id_suffix = next_address()
        z3_int = z3.Int(f"{name}_{id_suffix}_int")
        z3_bool = z3.Bool(f"{name}_{id_suffix}_bool")
        z3_str = z3.String(f"{name}_{id_suffix}_str")
        z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
        z3_float = z3.FP(f"{name}_{id_suffix}_float", z3.Float64())
        is_int = z3.Bool(f"{name}_{id_suffix}_is_int")
        is_bool = z3.Bool(f"{name}_{id_suffix}_is_bool")
        is_str = z3.Bool(f"{name}_{id_suffix}_is_str")
        is_path = z3.Bool(f"{name}_{id_suffix}_is_path")
        is_obj = z3.Bool(f"{name}_{id_suffix}_is_obj")
        is_none = z3.Bool(f"{name}_{id_suffix}_is_none")
        is_float = z3.Bool(f"{name}_{id_suffix}_is_float")
        is_list = z3.Bool(f"{name}_{id_suffix}_is_list")
        is_dict = z3.Bool(f"{name}_{id_suffix}_is_dict")

        type_vars = [is_int, is_bool, is_str, is_path, is_obj, is_none, is_float, is_list, is_dict]
        type_constraint = exactly_one_bool(type_vars)

        result = (
            SymbolicValue(
                z3_int=z3_int,
                is_int=is_int,
                z3_bool=z3_bool,
                is_bool=is_bool,
                z3_str=z3_str,
                is_str=is_str,
                z3_addr=z3_addr,
                is_obj=is_obj,
                is_path=is_path,
                is_none=is_none,
                z3_float=z3_float,
                is_float=is_float,
                is_list=is_list,
                is_dict=is_dict,
                _name=name,
            ),
            type_constraint,
        )
        return result

    @staticmethod
    def symbolic_int(name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create an integer-affinity carrier with a tautological constraint."""
        z3_int = z3.Int(f"{name}_int")
        sv = SymbolicValue(
            _name=name,
            z3_int=z3_int,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type="int",
        )
        if name.lower().startswith(("self", "cls")):
            setattr(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def symbolic_float(name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a Float64 FP-affinity carrier with a tautological constraint."""
        sv = SymbolicValue(
            _name=name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=z3.FP(f"{name}_float", z3.Float64()),
            is_float=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type="float",
        )
        if name.lower().startswith(("self", "cls")):
            setattr(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def symbolic_bool(name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a Boolean-affinity carrier with a tautological constraint."""
        z3_bool = z3.Bool(f"{name}_bool")
        sv = SymbolicValue(
            _name=name,
            z3_int=z3.If(z3_bool, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=z3_bool,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type="bool",
        )
        if name.lower().startswith(("self", "cls")):
            setattr(sv, "_h_active", True)
        return sv, Z3_TRUE

    @staticmethod
    def from_z3(expr: z3.ExprRef, name: str | None = None) -> _SymbolicValueType:
        """Wrap Boolean or arithmetic expressions in a unified scalar carrier.

        Limitations:
            Expressions outside those two recognized categories become a
            carrier with no asserted active type.
        """
        if name is None:
            name = str(expr)
        if isinstance(expr, z3.BoolRef):
            return SymbolicValue(
                _name=name,
                z3_int=z3.If(expr, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=expr,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
            )
        elif isinstance(expr, z3.ArithRef):
            return SymbolicValue(
                _name=name,
                z3_int=expr,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
            )
        else:
            return SymbolicValue(
                _name=name,
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
            )

    @staticmethod
    def symbolic_path(name: str) -> tuple[_SymbolicValueType, z3.BoolRef]:
        """Create a unified value constrained to its path discriminator.

        Notes:
            Callers must add the returned constraint to preserve path typing.
        """
        val, constraint = SymbolicValue.symbolic(name)
        path_constraint = z3.And(constraint, val.is_path)

        if not getattr(val, "_h_active", False) and name:
            if name.lower().startswith(("self", "cls")):
                setattr(val, "_h_active", True)

        return val, path_constraint
