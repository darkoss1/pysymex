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

"""Binary FP arithmetic slots for symbolic floats."""

from __future__ import annotations

from fractions import Fraction
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.numeric.floating.core import FloatCoreMixin, new_like

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


def _concrete_fp_value(expr: z3.FPRef) -> float | None:
    """Return a Python float for an FP literal, or ``None`` when symbolic."""
    if not z3.is_fp_value(expr):
        return None
    if expr.isNaN():
        return float("nan")
    if expr.isInf():
        return float("-inf") if expr.isNegative() else float("inf")
    if expr.isZero():
        return -0.0 if expr.isNegative() else 0.0
    real = z3.simplify(z3.fpToReal(expr))
    if not isinstance(real, z3.RatNumRef):
        return None
    return float(Fraction(real.numerator_as_long(), real.denominator_as_long()))


def _python_float_result(value: complex) -> float:
    """Reject concrete power results unsupported by the float carrier."""
    if isinstance(value, complex):
        msg = "complex exponentiation results are not supported by SymbolicFloat"
        raise TypeError(msg)
    return value


class FloatBinaryArithmeticMixin(FloatCoreMixin):
    """FP binary arithmetic operations."""

    def __add__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpAdd(self._rm, self._expr, self._to_fp(other)))

    def __radd__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return self.__add__(other)

    def __sub__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpSub(self._rm, self._expr, self._to_fp(other)))

    def __rsub__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpSub(self._rm, self._to_fp(other), self._expr))

    def __mul__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpMul(self._rm, self._expr, self._to_fp(other)))

    def __rmul__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return self.__mul__(other)

    def __truediv__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpDiv(self._rm, self._expr, self._to_fp(other)))

    def __rtruediv__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        return new_like(self, z3.fpDiv(self._rm, self._to_fp(other), self._expr))

    def __floordiv__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        div_expr = z3.fpDiv(self._rm, self._expr, self._to_fp(other))
        return new_like(self, z3.fpRoundToIntegral(z3.RTN(), div_expr))

    def __rfloordiv__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        div_expr = z3.fpDiv(self._rm, self._to_fp(other), self._expr)
        return new_like(self, z3.fpRoundToIntegral(z3.RTN(), div_expr))

    def __mod__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        left_value = _concrete_fp_value(self._expr)
        right_value = _concrete_fp_value(other_fp)
        if left_value is not None and right_value is not None:
            return new_like(self, z3.FPVal(left_value % right_value, self._sort))
        return new_like(self, self._mod_expr(self._expr, other_fp))

    def __rmod__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        left_value = _concrete_fp_value(other_fp)
        right_value = _concrete_fp_value(self._expr)
        if left_value is not None and right_value is not None:
            return new_like(self, z3.FPVal(left_value % right_value, self._sort))
        return new_like(self, self._mod_expr(other_fp, self._expr))

    def _mod_expr(self, left: z3.FPRef, right: z3.FPRef) -> z3.FPRef:
        """Encode Python remainder for finite operands without FP quotient rounding."""
        left_real = z3.fpToReal(left)
        right_real = z3.fpToReal(right)
        quotient = z3.ToInt(left_real / right_real)
        finite_result = z3.fpToFP(
            self._rm,
            left_real - z3.ToReal(quotient) * right_real,
            self._sort,
        )
        finite_result = z3.If(
            z3.fpIsZero(finite_result),
            z3.If(z3.fpIsNegative(right), z3.fpMinusZero(self._sort), z3.fpPlusZero(self._sort)),
            finite_result,
        )
        nan = z3.fpNaN(self._sort)
        same_sign = z3.fpIsNegative(left) == z3.fpIsNegative(right)
        infinite_divisor_result = z3.If(
            z3.fpIsZero(left),
            z3.If(z3.fpIsNegative(right), z3.fpMinusZero(self._sort), z3.fpPlusZero(self._sort)),
            z3.If(same_sign, left, right),
        )
        return z3.If(
            z3.Or(z3.fpIsNaN(left), z3.fpIsNaN(right), z3.fpIsInf(left), z3.fpIsZero(right)),
            nan,
            z3.If(z3.fpIsInf(right), infinite_divisor_result, finite_result),
        )

    def __pow__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        base_value = _concrete_fp_value(self._expr)
        exponent_value = _concrete_fp_value(other_fp)
        if base_value is not None and exponent_value is not None:
            result = _python_float_result(base_value**exponent_value)
            return new_like(self, z3.FPVal(result, self._sort))
        if exponent_value is None or not exponent_value.is_integer():
            return NotImplemented
        real_base = z3.fpToReal(self._expr)
        res_real = real_base ** int(exponent_value)
        result = z3.fpToFP(self._rm, res_real, self._sort)
        if exponent_value < 0:
            result = z3.If(z3.fpIsZero(self._expr), z3.fpNaN(self._sort), result)
        return new_like(self, result)

    def __rpow__(self, other: SymbolicFloat | SymbolicInt | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        base_value = _concrete_fp_value(other_fp)
        exponent_value = _concrete_fp_value(self._expr)
        if base_value is not None and exponent_value is not None:
            result = _python_float_result(base_value**exponent_value)
            return new_like(self, z3.FPVal(result, self._sort))
        if exponent_value is None or not exponent_value.is_integer():
            return NotImplemented
        real_base = z3.fpToReal(other_fp)
        res_real = real_base ** int(exponent_value)
        result = z3.fpToFP(self._rm, res_real, self._sort)
        if exponent_value < 0:
            result = z3.If(z3.fpIsZero(other_fp), z3.fpNaN(self._sort), result)
        return new_like(self, result)
