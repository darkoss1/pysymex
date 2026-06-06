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

"""Z3 FP-backed symbolic floating-point value."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.config.floats import FloatConfig, get_fp_sort

if TYPE_CHECKING:
    from pysymex.core.types.scalars.values import AnySymbolic


class AdvancedSymbolicFloat:
    """Floating-point value represented by Z3 FP theory.

    Arithmetic and conversions use the configured FP precision and rounding
    mode, retaining IEEE distinctions such as NaN, infinities, subnormals,
    and signed zero.

    Limitations:
        Operations create expressions only; they do not themselves test path
        feasibility or classify an exceptional floating-point result.
    """

    _counter = 0

    def __init__(
        self,
        name: str | None = None,
        value: float | None = None,
        z3_expr: z3.FPRef | None = None,
        config: FloatConfig | None = None,
    ) -> None:
        """Initialize from an FP expression, concrete float, or fresh FP symbol."""
        self.config = config or FloatConfig()
        self._sort = get_fp_sort(self.config.precision)
        self._rm = self.config.get_rounding_mode()
        if z3_expr is not None:
            self._expr = z3_expr
            self.name = name or f"fp_{AdvancedSymbolicFloat._counter}"
        elif value is not None:
            self._expr = z3.FPVal(value, self._sort)
            self.name = name or f"fp_const_{value}"
        else:
            AdvancedSymbolicFloat._counter += 1
            self.name = name or f"fp_{AdvancedSymbolicFloat._counter}"
            self._expr = z3.FP(self.name, self._sort)

    @property
    def z3_expr(self) -> z3.FPRef:
        """Return the underlying Z3 floating-point expression."""
        return self._expr

    def __add__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return FP addition in this value's configured rounding mode."""
        other_expr = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpAdd(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __radd__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return commutative reflected FP addition."""
        return self.__add__(other)

    def __sub__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return FP subtraction in this value's configured rounding mode."""
        other_expr = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpSub(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rsub__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return reflected FP subtraction."""
        other_fp = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpSub(self._rm, other_fp, self._expr),
            config=self.config,
        )

    def __mul__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return FP multiplication in this value's configured rounding mode."""
        other_expr = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpMul(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rmul__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return commutative reflected FP multiplication."""
        return self.__mul__(other)

    def __truediv__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return FP division without querying feasibility or classifying results."""
        other_expr = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpDiv(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rtruediv__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return ``other / self`` in this value's configured FP sort."""
        other_fp = self._to_fp(other)
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpDiv(self._rm, other_fp, self._expr),
            config=self.config,
        )

    def __floordiv__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return FP division rounded toward negative infinity to an integral FP value."""
        other_expr = self._to_fp(other)

        div_expr = z3.fpDiv(self._rm, self._expr, other_expr)

        floored = z3.fpRoundToIntegral(z3.RTN(), div_expr)
        return AdvancedSymbolicFloat(
            z3_expr=floored,
            config=self.config,
        )

    def __rfloordiv__(self, other: AdvancedSymbolicFloat | float) -> AdvancedSymbolicFloat:
        """Return reflected integral FP division rounded toward negative infinity."""
        other_fp = self._to_fp(other)
        div_expr = z3.fpDiv(self._rm, other_fp, self._expr)
        floored = z3.fpRoundToIntegral(z3.RTN(), div_expr)
        return AdvancedSymbolicFloat(
            z3_expr=floored,
            config=self.config,
        )

    def __neg__(self) -> AdvancedSymbolicFloat:
        """Return FP sign negation."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpNeg(self._expr),
            config=self.config,
        )

    def __abs__(self) -> AdvancedSymbolicFloat:
        """Return FP absolute value."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpAbs(self._expr),
            config=self.config,
        )

    def __lt__(self, other: AdvancedSymbolicFloat | float) -> z3.BoolRef:
        """Return the Z3 FP less-than predicate."""
        other_expr = self._to_fp(other)
        return z3.fpLT(self._expr, other_expr)

    def __le__(self, other: AdvancedSymbolicFloat | float) -> z3.BoolRef:
        """Return the Z3 FP less-than-or-equal predicate."""
        other_expr = self._to_fp(other)
        return z3.fpLEQ(self._expr, other_expr)

    def __gt__(self, other: AdvancedSymbolicFloat | float) -> z3.BoolRef:
        """Return the Z3 FP greater-than predicate."""
        other_expr = self._to_fp(other)
        return z3.fpGT(self._expr, other_expr)

    def __ge__(self, other: AdvancedSymbolicFloat | float) -> z3.BoolRef:
        """Return the Z3 FP greater-than-or-equal predicate."""
        other_expr = self._to_fp(other)
        return z3.fpGEQ(self._expr, other_expr)

    def __eq__(self, other: object) -> z3.BoolRef:  # pyright: ignore[reportIncompatibleMethodOverride]
        """Return symbolic FP equality for supported numeric operands."""
        if isinstance(other, (AdvancedSymbolicFloat, float, int)):
            other_expr = self._to_fp(other)
            return z3.fpEQ(self._expr, other_expr)
        return NotImplemented

    def __ne__(self, other: object) -> z3.BoolRef:  # pyright: ignore[reportIncompatibleMethodOverride]
        """Return symbolic FP inequality for supported numeric operands."""
        if isinstance(other, (AdvancedSymbolicFloat, float, int)):
            other_expr = self._to_fp(other)
            return z3.Not(z3.fpEQ(self._expr, other_expr))
        return NotImplemented

    def is_nan(self) -> z3.BoolRef:
        """Check if value is NaN."""
        return z3.fpIsNaN(self._expr)

    def is_infinity(self) -> z3.BoolRef:
        """Check if value is infinity (+inf or -inf)."""
        return z3.fpIsInf(self._expr)

    def is_positive_infinity(self) -> z3.BoolRef:
        """Check if value is positive infinity."""
        return z3.And(z3.fpIsInf(self._expr), z3.fpIsPositive(self._expr))

    def is_negative_infinity(self) -> z3.BoolRef:
        """Check if value is negative infinity."""
        return z3.And(z3.fpIsInf(self._expr), z3.fpIsNegative(self._expr))

    def is_zero(self) -> z3.BoolRef:
        """Check if value is zero (+0 or -0)."""
        return z3.fpIsZero(self._expr)

    def is_positive_zero(self) -> z3.BoolRef:
        """Check if value is positive zero."""
        return z3.And(z3.fpIsZero(self._expr), z3.fpIsPositive(self._expr))

    def is_negative_zero(self) -> z3.BoolRef:
        """Check if value is negative zero."""
        return z3.And(z3.fpIsZero(self._expr), z3.fpIsNegative(self._expr))

    def is_denormal(self) -> z3.BoolRef:
        """Check if value is denormalized (subnormal)."""
        return z3.fpIsSubnormal(self._expr)

    def is_normal(self) -> z3.BoolRef:
        """Return whether the FP value is normal rather than subnormal or special."""
        return z3.fpIsNormal(self._expr)

    def is_positive(self) -> z3.BoolRef:
        """Return Z3's positive-sign predicate for this FP expression."""
        return z3.fpIsPositive(self._expr)

    def is_negative(self) -> z3.BoolRef:
        """Return Z3's negative-sign predicate for this FP expression."""
        return z3.fpIsNegative(self._expr)

    def sqrt(self) -> AdvancedSymbolicFloat:
        """Square root."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpSqrt(self._rm, self._expr),
            config=self.config,
        )

    def fma(self, mul: AdvancedSymbolicFloat, add: AdvancedSymbolicFloat) -> AdvancedSymbolicFloat:
        """Fused multiply-add: self * mul + add."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpFMA(self._rm, self._expr, mul._expr, add._expr),
            config=self.config,
        )

    def min(self, other: AdvancedSymbolicFloat) -> AdvancedSymbolicFloat:
        """Minimum of two values."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpMin(self._expr, other._expr),
            config=self.config,
        )

    def max(self, other: AdvancedSymbolicFloat) -> AdvancedSymbolicFloat:
        """Maximum of two values."""
        return AdvancedSymbolicFloat(
            z3_expr=z3.fpMax(self._expr, other._expr),
            config=self.config,
        )

    def to_int(self) -> z3.ArithRef:
        """Return signed 64-bit, round-toward-zero integer conversion.

        Limitations:
            This is a bounded Z3 FP-to-bit-vector conversion, not Python's
            arbitrary-width ``int(float_value)`` semantics for all values.
        """
        bv = z3.fpToSBV(z3.RTZ(), self._expr, z3.BitVecSort(64))
        return z3.BV2Int(bv, is_signed=True)

    def hash_value(self) -> int:
        """Return a structural hash of the Z3 FP expression."""
        return self._expr.hash()

    def conditional_merge(
        self, other: AdvancedSymbolicFloat | float | int, condition: z3.BoolRef
    ) -> AnySymbolic:
        """Return an FP expression selected by ``condition``.

        Notes:
            This method does not assert the condition or establish that either
            branch is feasible.
        """
        other_fp = self._to_fp(other)
        return cast(
            "AnySymbolic",
            AdvancedSymbolicFloat(
                z3_expr=z3.If(condition, self._expr, other_fp),
                config=self.config,
            ),
        )

    def _to_fp(self, value: AdvancedSymbolicFloat | float | int) -> z3.FPRef:
        """Convert a value into this instance's FP sort and rounding context."""
        if isinstance(value, AdvancedSymbolicFloat):
            if value._sort == self._sort:
                return value._expr

            return z3.fpToFP(self._rm, value._expr, self._sort)
        return z3.FPVal(float(value), self._sort)

    def __repr__(self) -> str:
        """Return the diagnostic representation for this FP carrier."""
        return f"AdvancedSymbolicFloat({self.name})"
