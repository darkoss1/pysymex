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

"""Unary and remainder-style arithmetic for scalar symbolic values."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.logger import get_logger
from pysymex.core.constants import Z3_FALSE, Z3_FLOAT_ONE, Z3_FLOAT_ZERO, Z3_TRUE, Z3_ZERO

logger = get_logger(__name__)
from pysymex.core.types.scalars.value.helpers import (
    concrete_numeric_is_nonzero as _concrete_numeric_is_nonzero,
    guarded_nonzero_divisor as _guarded_nonzero_divisor,
    py_floor_div as _py_floor_div,
    py_mod as _py_mod,
    is_concrete_val,
)

from pysymex.core.types.scalars.value.protocols import SymbolicValueConstructor, SymbolicValueSelf


SymbolicValue = cast(SymbolicValueConstructor, object)


def bind_symbolic_value_class(value_cls: SymbolicValueConstructor) -> None:
    """Bind the concrete unified carrier constructed by remainder operations."""
    global SymbolicValue
    SymbolicValue = value_cls


class SymbolicValueRemainderMixin:
    """Implement unary negation, remainder, and floor division carriers."""

    def __neg__(self: SymbolicValueSelf) -> SymbolicValueSelf:
        """Return a negated integer or FP payload while retaining type predicates."""
        self_affinity = self.affinity_type

        if self_affinity == "int":
            return SymbolicValue(
                _name=f"(-{self.name})",
                z3_int=-self.z3_int,
                is_int=Z3_TRUE,
                z3_float=Z3_FLOAT_ZERO,
                is_float=Z3_FALSE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="int",
            )

        if self_affinity == "float":
            return SymbolicValue(
                _name=f"(-{self.name})",
                z3_int=Z3_ZERO,
                is_int=Z3_FALSE,
                z3_float=z3.fpNeg(self.z3_float),
                is_float=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                affinity_type="float",
            )

        return SymbolicValue(
            _name=f"(-{self.name})",
            z3_int=-self.z3_int,
            is_int=self.is_int,
            z3_float=z3.fpNeg(self.z3_float),
            is_float=self.is_float,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def __mod__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return the modeled remainder carrier for numeric values.

        Limitations:
            Definite concrete integer zero raises. For unresolved zero
            divisors, integer payloads use zero and FP payloads use NaN on the
            zero branch; this method does not emit the corresponding exception
            path.
        """
        if is_concrete_val(self) and is_concrete_val(other):
            try:
                lhs_const = self._constant_value
                cv_other = getattr(other, "_constant_value", other)
                if (
                    isinstance(lhs_const, (int, float, bool))
                    and isinstance(cv_other, (int, float, bool))
                    and cv_other != 0
                ):
                    return SymbolicValue.from_const(lhs_const % cv_other)
            except (AttributeError, TypeError, ZeroDivisionError):
                logger.debug(
                    "Concrete modulo fast path unavailable; using symbolic encoding",
                    exc_info=True,
                )
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
                raise ZeroDivisionError("division by zero")
            cv = getattr(other, "_constant_value", None)
            safe_divisor = (
                other.z3_int
                if _concrete_numeric_is_nonzero(cv)
                else (_guarded_nonzero_divisor(other.z3_int))
            )
            raw_res = _py_mod(self.z3_int, safe_divisor)
            guarded_res = (
                raw_res
                if _concrete_numeric_is_nonzero(cv)
                else z3.If(other.z3_int != 0, raw_res, Z3_ZERO)
            )
            return SymbolicValue(
                _name=f"({self.name}%{other.name})",
                z3_int=guarded_res,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=Z3_FLOAT_ZERO,
                is_float=Z3_FALSE,
                affinity_type="int",
            )

        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        cv = getattr(other, "_constant_value", None)
        safe_divisor = (
            other.z3_int
            if _concrete_numeric_is_nonzero(cv)
            else (_guarded_nonzero_divisor(other.z3_int))
        )
        raw_res = _py_mod(self.z3_int, safe_divisor)
        if _concrete_numeric_is_nonzero(cv):
            guarded_res = raw_res
        else:
            guarded_res = z3.If(other.z3_int != 0, raw_res, Z3_ZERO)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            guarded_fp_res = Z3_FLOAT_ZERO
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

            safe_right_fp = z3.If(z3.fpIsZero(right_fp), Z3_FLOAT_ONE, right_fp)
            raw_fp_div = z3.fpDiv(z3.RNE(), left_fp, safe_right_fp)
            fp_floored = z3.fpRoundToIntegral(z3.RTN(), raw_fp_div)
            fp_mod_res = z3.fpSub(z3.RNE(), left_fp, z3.fpMul(z3.RNE(), fp_floored, safe_right_fp))
            guarded_fp_res = z3.If(
                z3.Not(z3.fpIsZero(right_fp)), fp_mod_res, z3.fpNaN(z3.Float64())
            )

            is_float_res = z3.And(
                z3.Or(self.is_float, other.is_float),
                z3.Or(self.is_int, self.is_bool, self.is_float),
                z3.Or(other.is_int, other.is_bool, other.is_float),
            )

        return SymbolicValue(
            _name=f"({self.name}%{other.name})",
            z3_int=guarded_res,
            is_int=z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool)),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=guarded_fp_res,
            is_float=is_float_res,
            affinity_type="float",
        )

    def __floordiv__(self: SymbolicValueSelf, other: object) -> SymbolicValueSelf:
        """Return the modeled floor-division carrier for numeric values.

        Limitations:
            Definite concrete integer zero raises. For unresolved zero
            divisors, integer payloads use zero and FP payloads use NaN on the
            zero branch; this method does not emit the corresponding exception
            path.
        """
        if is_concrete_val(self) and is_concrete_val(other):
            try:
                lhs_const = self._constant_value
                cv_other = getattr(other, "_constant_value", other)
                if (
                    isinstance(lhs_const, (int, float, bool))
                    and isinstance(cv_other, (int, float, bool))
                    and cv_other != 0
                ):
                    return SymbolicValue.from_const(lhs_const // cv_other)
            except (AttributeError, TypeError, ZeroDivisionError):
                logger.debug(
                    "Concrete floor-division fast path unavailable; using symbolic encoding",
                    exc_info=True,
                )
        other = SymbolicValue.from_const(other)

        self_affinity = self.affinity_type
        other_affinity = other.affinity_type

        if self_affinity == "int" and other_affinity == "int":
            if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
                raise ZeroDivisionError("division by zero")
            cv = getattr(other, "_constant_value", None)
            safe_divisor = (
                other.z3_int
                if _concrete_numeric_is_nonzero(cv)
                else (_guarded_nonzero_divisor(other.z3_int))
            )
            raw_res = _py_floor_div(self.z3_int, safe_divisor)
            guarded_res = (
                raw_res
                if _concrete_numeric_is_nonzero(cv)
                else z3.If(other.z3_int != 0, raw_res, Z3_ZERO)
            )
            return SymbolicValue(
                _name=f"({self.name}//{other.name})",
                z3_int=guarded_res,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
                z3_float=Z3_FLOAT_ZERO,
                is_float=Z3_FALSE,
                affinity_type="int",
            )

        if z3.is_int_value(other.z3_int) and other.z3_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        cv = getattr(other, "_constant_value", None)
        safe_divisor = (
            other.z3_int
            if _concrete_numeric_is_nonzero(cv)
            else (_guarded_nonzero_divisor(other.z3_int))
        )
        raw_res = _py_floor_div(self.z3_int, safe_divisor)
        if _concrete_numeric_is_nonzero(cv):
            guarded_res = raw_res
        else:
            guarded_res = z3.If(other.z3_int != 0, raw_res, Z3_ZERO)

        if z3.is_false(self.is_float) and z3.is_false(other.is_float):
            guarded_fp_res = Z3_FLOAT_ZERO
            is_float_res = z3.Not(z3.And(self.is_int, other.is_int))
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

            safe_right_fp = z3.If(z3.fpIsZero(right_fp), Z3_FLOAT_ONE, right_fp)
            raw_fp_div = z3.fpDiv(z3.RNE(), left_fp, safe_right_fp)

            fp_floored = z3.fpRoundToIntegral(z3.RTN(), raw_fp_div)
            guarded_fp_res = z3.If(
                z3.Not(z3.fpIsZero(right_fp)), fp_floored, z3.fpNaN(z3.Float64())
            )
            is_float_res = z3.Not(z3.And(self.is_int, other.is_int))

        return SymbolicValue(
            _name=f"({self.name}//{other.name})",
            z3_int=guarded_res,
            is_int=z3.And(z3.Or(self.is_int, self.is_bool), z3.Or(other.is_int, other.is_bool)),
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            z3_float=guarded_fp_res,
            is_float=is_float_res,
            is_path=Z3_FALSE,
            affinity_type="float",
        )
