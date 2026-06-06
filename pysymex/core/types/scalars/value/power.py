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

"""Power operator for scalar symbolic values."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.scalars.value.helpers import (
    apply_concrete_numeric_binary_op as _apply_concrete_numeric_binary_op,
)

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf


SymbolicValue = cast(SymbolicValueConstructor, object)


def bind_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by exponentiation."""
    global SymbolicValue
    SymbolicValue = value_cls


class SymbolicValuePowerMixin:
    """Build exponentiation result channels for modeled numeric values."""

    def __pow__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return concrete Python exponentiation or encoded symbolic power.

        Limitations:
            A symbolic integer-affinity exponent is retained as an integer
            result channel without separately excluding negative exponents;
            Float64 conversion is used for represented float result branches.
        """
        concrete = _apply_concrete_numeric_binary_op(self, other, lambda a, b: a**b)
        if concrete is not None:
            return concrete
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            res_int = self.z3_int**other.z3_int
            return SymbolicValue(
                _name=f"({self.name}**{other.name})",
                z3_int=res_int,
                is_int=Z3_TRUE,
                z3_float=z3.FPVal(0.0, z3.Float64()),
                is_float=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="int",
            )

        res_int = self.z3_int**other.z3_int
        is_int_res = z3.And(
            z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool), other.z3_int >= 0
        )

        self_real = z3.ToReal(self.z3_int)
        other_real = z3.ToReal(other.z3_int)

        real_base = z3.If(self.is_float, z3.fpToReal(self.z3_float), self_real)
        real_exp = z3.If(other.is_float, z3.fpToReal(other.z3_float), other_real)

        res_real = real_base**real_exp
        res_float = z3.fpToFP(z3.RNE(), res_real, z3.Float64())

        is_float_res = z3.And(
            z3.Or(self.is_int, self.is_bool, self.is_float),
            z3.Or(other.is_int, other.is_bool, other.is_float),
            z3.Or(
                self.is_float,
                other.is_float,
                z3.And(
                    z3.Or(self.is_int, self.is_bool),
                    z3.Or(other.is_int, other.is_bool),
                    other.z3_int < 0,
                ),
            ),
        )

        return SymbolicValue(
            _name=f"({self.name}**{other.name})",
            z3_int=res_int,
            is_int=is_int_res,
            z3_float=res_float,
            is_float=is_float_res,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            affinity_type="float",
        )
