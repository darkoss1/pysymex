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

"""Addition, subtraction, and multiplication for scalar symbolic values."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.constants import (
    Z3_EMPTY_STRING,
    Z3_FALSE,
    Z3_FLOAT_ZERO,
    Z3_ONE,
    Z3_TRUE,
    Z3_ZERO,
)

from pysymex.core.types.scalars.value.helpers import (
    apply_concrete_numeric_binary_op as _apply_concrete_numeric_binary_op,
)
from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf


SymbolicValue = cast(SymbolicValueConstructor, object)


def bind_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by additive operators."""
    global SymbolicValue
    SymbolicValue = value_cls


class SymbolicValueAdditiveMixin:
    """Build additive result channels for represented scalar operand types.

    Limitations:
        Unsupported operand combinations produce a carrier with inactive
        result-type predicates here; this mixin does not emit Python
        ``TypeError`` paths for those combinations.
    """

    def __add__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return integer, Float64, or string-concatenation channels when applicable."""
        concrete = _apply_concrete_numeric_binary_op(self, other, lambda a, b: a + b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self.name}+{other.name})",
                z3_int=self.z3_int + other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "bool" and other_affinity == "bool":
            return SymbolicValue(
                _name=f"({self.name}+{other.name})",
                z3_int=z3.If(self.z3_bool, Z3_ONE, Z3_ZERO) + z3.If(other.z3_bool, Z3_ONE, Z3_ZERO),
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )

        res_int = self.z3_int + other.z3_int
        is_int_like_self = z3.Or(self.is_int, self.is_bool)
        is_int_like_other = z3.Or(other.is_int, other.is_bool)
        is_int_res = z3.And(is_int_like_self, is_int_like_other)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = Z3_FLOAT_ZERO
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpAdd(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        if z3.is_false(self.is_str) and z3.is_false(other.is_str):
            res_str = Z3_EMPTY_STRING
            is_str_res = Z3_FALSE
        else:
            res_str = cast(
                z3.SeqRef,
                z3.If(
                    z3.And(self.is_str, other.is_str),
                    z3.Concat(self.z3_str, other.z3_str),
                    Z3_EMPTY_STRING,
                ),
            )
            is_str_res = z3.And(self.is_str, other.is_str)

        return SymbolicValue(
            _name=f"({self.name}+{other.name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_str=res_str,
            is_str=is_str_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __sub__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return integer or Float64 subtraction channels when applicable."""
        concrete = _apply_concrete_numeric_binary_op(self, other, lambda a, b: a - b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self.name}-{other.name})",
                z3_int=self.z3_int - other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        res_int = self.z3_int - other.z3_int
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = Z3_FLOAT_ZERO
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpSub(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        return SymbolicValue(
            _name=f"({self.name}-{other.name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )

    def __mul__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return integer or Float64 multiplication channels when applicable."""
        concrete = _apply_concrete_numeric_binary_op(self, other, lambda a, b: a * b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            return SymbolicValue(
                _name=f"({self.name}*{other.name})",
                z3_int=self.z3_int * other.z3_int,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                is_str=Z3_FALSE,
                is_float=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
                affinity_type="int",
            )

        res_int = self.z3_int * other.z3_int
        is_int_res = z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool))

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            res_float = Z3_FLOAT_ZERO
            is_float_res = Z3_FALSE
        else:
            left_fp = z3.If(
                self.is_float,
                self.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64()),
            )
            right_fp = z3.If(
                other.is_float,
                other.z3_float,
                z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64()),
            )
            res_float = z3.fpMul(z3.RNE(), left_fp, right_fp)
            is_float_res = z3.Or(self.is_float, other.is_float)

        return SymbolicValue(
            _name=f"({self.name}*{other.name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_addr=Z3_ZERO,
            is_obj=Z3_FALSE,
            is_list=Z3_FALSE,
            is_dict=Z3_FALSE,
            is_path=Z3_FALSE,
            is_none=Z3_FALSE,
        )
