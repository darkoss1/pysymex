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

from pysymex._internal.core.constants import (
    Z3_BYTE_SORT,
    Z3_FALSE,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.types.scalars.value.protocols import (
    SymbolicValueSelf,
    ValueConstructor,
    unbound_symbolic_value_constructor,
)
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.core.types.scalars.values import SymbolicValue

_symbolic_value_cls = unbound_symbolic_value_constructor()
_symbolic_string_cls: type[object] = object


def bind_creator_symbolic_value_classes(
    value_cls: ValueConstructor,
    string_cls: type[object],
) -> None:
    """Bind carrier classes used by symbolic-value construction."""
    global _symbolic_value_cls, _symbolic_string_cls
    _symbolic_value_cls = value_cls
    _symbolic_string_cls = string_cls


class SymbolicValueCreatorMixin:
    """Create unified scalar carriers and their required type constraints."""

    def as_string(self: SymbolicValueSelf) -> SymbolicString:
        """Return a string view that delegates storage and truthiness to this value."""
        from pysymex._internal.core.types.scalars.strings import SymbolicString as _SymbolicString

        return _SymbolicString(
            _z3_str=self.z3_str,
            _z3_len=z3.Length(self.z3_str),
            _name=self.name,
            _unified=cast("SymbolicValue", self),
        )

    @staticmethod
    def symbolic(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create an unconstrained carrier plus an exactly-one-type constraint.

        Notes:
            Callers must add the returned constraint before relying on a
            single active type discriminator.

        """
        id_suffix = next_address()
        z3_int = z3.Int(f"{name}_{id_suffix}_int")
        z3_bool = z3.Bool(f"{name}_{id_suffix}_bool")
        z3_str = z3.String(f"{name}_{id_suffix}_str")
        z3_bytes = z3.Const(f"{name}_{id_suffix}_bytes", z3.SeqSort(Z3_BYTE_SORT))
        z3_addr = z3.Int(f"{name}_{id_suffix}_addr")
        z3_float = z3.FP(f"{name}_{id_suffix}_float", z3.Float64())
        is_int = z3.Bool(f"{name}_{id_suffix}_is_int")
        is_bool = z3.Bool(f"{name}_{id_suffix}_is_bool")
        is_str = z3.Bool(f"{name}_{id_suffix}_is_str")
        is_bytes = z3.Bool(f"{name}_{id_suffix}_is_bytes")
        is_path = z3.Bool(f"{name}_{id_suffix}_is_path")
        is_obj = z3.Bool(f"{name}_{id_suffix}_is_obj")
        is_none = z3.Bool(f"{name}_{id_suffix}_is_none")
        is_float = z3.Bool(f"{name}_{id_suffix}_is_float")
        is_list = z3.Bool(f"{name}_{id_suffix}_is_list")
        is_dict = z3.Bool(f"{name}_{id_suffix}_is_dict")
        is_tuple = z3.Bool(f"{name}_{id_suffix}_is_tuple")
        is_set = z3.Bool(f"{name}_{id_suffix}_is_set")

        type_vars = [
            is_int,
            is_bool,
            is_str,
            is_bytes,
            is_path,
            is_obj,
            is_none,
            is_float,
            is_list,
            is_dict,
            is_tuple,
            is_set,
        ]
        type_constraint = z3.And(
            ScalarValueOps.exactly_one_bool(type_vars),
            z3.Implies(z3.Or(is_list, is_dict, is_tuple, is_set), z3_int >= 0),
        )

        return (
            _symbolic_value_cls(
                z3_int=z3_int,
                is_int=is_int,
                z3_bool=z3_bool,
                is_bool=is_bool,
                z3_str=z3_str,
                is_str=is_str,
                z3_bytes=z3_bytes,
                is_bytes=is_bytes,
                z3_addr=z3_addr,
                is_obj=is_obj,
                is_path=is_path,
                is_none=is_none,
                z3_float=z3_float,
                is_float=is_float,
                is_list=is_list,
                is_dict=is_dict,
                is_tuple=is_tuple,
                is_set=is_set,
                _name=name,
            ),
            type_constraint,
        )

    @staticmethod
    def symbolic_int(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create an integer-affinity carrier with a tautological constraint."""
        z3_int = z3.Int(f"{name}_int")
        sv = _symbolic_value_cls(
            _name=name,
            z3_int=z3_int,
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
            affinity_type="int",
        )
        if name.lower().startswith(("self", "cls")):
            sv.mark_receiver_active()
        return sv, Z3_TRUE

    @staticmethod
    def symbolic_float(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a Float64 FP-affinity carrier with a tautological constraint."""
        sv = _symbolic_value_cls(
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
            sv.mark_receiver_active()
        return sv, Z3_TRUE

    @staticmethod
    def symbolic_bool(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a Boolean-affinity carrier with a tautological constraint."""
        z3_bool = z3.Bool(f"{name}_bool")
        sv = _symbolic_value_cls(
            _name=name,
            z3_int=z3.If(z3_bool, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=z3_bool,
            is_bool=Z3_TRUE,
            is_path=Z3_FALSE,
            affinity_type="bool",
        )
        if name.lower().startswith(("self", "cls")):
            sv.mark_receiver_active()
        return sv, Z3_TRUE

    @staticmethod
    def from_z3(expr: z3.ExprRef, name: str | None = None) -> SymbolicValue:
        """Wrap Boolean or arithmetic expressions in a unified scalar carrier.

        Limitations:
            Expressions outside those two recognized categories become a
            carrier with no asserted active type.
        """
        if name is None:
            name = str(expr)
        if isinstance(expr, z3.BoolRef):
            return _symbolic_value_cls(
                _name=name,
                z3_int=z3.If(expr, Z3_ONE, Z3_ZERO),
                is_int=Z3_FALSE,
                z3_bool=expr,
                is_bool=Z3_TRUE,
                is_path=Z3_FALSE,
            )
        if isinstance(expr, z3.ArithRef):
            return _symbolic_value_cls(
                _name=name,
                z3_int=expr,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_path=Z3_FALSE,
            )
        return _symbolic_value_cls(
            _name=name,
            z3_int=Z3_ZERO,
            is_int=Z3_FALSE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_path=Z3_FALSE,
        )

    @staticmethod
    def symbolic_path(name: str) -> tuple[SymbolicValue, z3.BoolRef]:
        """Create a unified value constrained to its path discriminator.

        Notes:
            Callers must add the returned constraint to preserve path typing.

        """
        val, constraint = _symbolic_value_cls.symbolic(name)
        path_constraint = z3.And(constraint, val.is_path)

        if not getattr(val, "_h_active", False) and name:
            if name.lower().startswith(("self", "cls")):
                val.mark_receiver_active()

        return val, path_constraint
