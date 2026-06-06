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

"""True division for scalar symbolic values."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_FLOAT_ONE, Z3_TRUE, Z3_ZERO

from pysymex.core.types.scalars.value.helpers import (
    concrete_numeric_is_nonzero as _concrete_numeric_is_nonzero,
    extract_concrete_numeric as _extract_concrete_numeric,
)
from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf


SymbolicValue = cast(SymbolicValueConstructor, object)


def bind_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by division."""
    global SymbolicValue
    SymbolicValue = value_cls


class SymbolicValueDivisionMixin:
    """Implement unified true division using Float64 FP result expressions."""

    def __truediv__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return a Float64 result carrier for modeled numeric true division.

        Limitations:
            Concrete zero division raises through the concrete or recognized
            integer-zero paths. An unresolved symbolic zero divisor is encoded
            as NaN on its zero branch; this method does not emit an exception
            path or constraint for that branch.
        """
        left_num = _extract_concrete_numeric(self)
        right_num = _extract_concrete_numeric(other)
        if left_num is not None and right_num is not None:
            return SymbolicValue.from_const(left_num / right_num)

        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if (self_affinity == "int" or self_affinity == "float") and (
            other_affinity == "int" or other_affinity == "float"
        ):
            if (
                other_affinity == "int"
                and z3.is_int_value(other.z3_int)
                and other.z3_int.as_long() == 0
            ):
                raise ZeroDivisionError("division by zero")
            cv = getattr(other, "_constant_value", None)

            if z3.is_false(self.is_float) and z3.is_false(other.is_float):
                left_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
                right_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
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

            if _concrete_numeric_is_nonzero(cv):
                guarded_float = z3.fpDiv(z3.RNE(), left_fp, right_fp)
                z3_int_placeholder = Z3_ZERO
            else:
                safe_right = z3.If(z3.fpIsZero(right_fp), Z3_FLOAT_ONE, right_fp)
                raw_float = z3.fpDiv(z3.RNE(), left_fp, safe_right)
                guarded_float = z3.If(
                    z3.Not(z3.fpIsZero(right_fp)), raw_float, z3.fpNaN(z3.Float64())
                )
                z3_int_placeholder = Z3_ZERO

            return SymbolicValue(
                _name=f"({self.name}/{other.name})",
                z3_int=z3_int_placeholder,
                is_int=Z3_FALSE,
                is_float=Z3_TRUE,
                z3_float=guarded_float,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="float",
            )

        if (
            other_affinity == "int"
            and z3.is_int_value(other.z3_int)
            and other.z3_int.as_long() == 0
        ):
            raise ZeroDivisionError("division by zero")

        cv = getattr(other, "_constant_value", None)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            left_fp = z3.fpToFP(z3.RNE(), z3.ToReal(self.z3_int), z3.Float64())
            right_fp = z3.fpToFP(z3.RNE(), z3.ToReal(other.z3_int), z3.Float64())
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

        if _concrete_numeric_is_nonzero(cv):
            guarded_float = z3.fpDiv(z3.RNE(), left_fp, right_fp)
            z3_int_placeholder = Z3_ZERO
        else:
            safe_right = z3.If(z3.fpIsZero(right_fp), Z3_FLOAT_ONE, right_fp)
            raw_float = z3.fpDiv(z3.RNE(), left_fp, safe_right)
            guarded_float = z3.If(z3.Not(z3.fpIsZero(right_fp)), raw_float, z3.fpNaN(z3.Float64()))
            z3_int_placeholder = Z3_ZERO

        return SymbolicValue(
            _name=f"({self.name}/{other.name})",
            z3_int=z3_int_placeholder,
            is_int=Z3_FALSE,
            is_float=Z3_TRUE,
            z3_float=guarded_float,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )
