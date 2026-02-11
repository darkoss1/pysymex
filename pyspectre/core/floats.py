"""Floating-point symbolic analysis for PySpectre.
This module provides symbolic reasoning about floating-point numbers
using Z3's FP theory.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
)
import z3

if TYPE_CHECKING:
    pass


class FloatPrecision(Enum):
    """Floating-point precision levels."""

    HALF = auto()
    SINGLE = auto()
    DOUBLE = auto()
    EXTENDED = auto()
    QUAD = auto()


def get_fp_sort(precision: FloatPrecision) -> z3.FPSortRef:
    """Get Z3 FP sort for a precision level."""
    if precision == FloatPrecision.HALF:
        return z3.FPSort(5, 11)
    elif precision == FloatPrecision.SINGLE:
        return z3.Float32()
    elif precision == FloatPrecision.DOUBLE:
        return z3.Float64()
    elif precision == FloatPrecision.EXTENDED:
        return z3.FPSort(15, 64)
    elif precision == FloatPrecision.QUAD:
        return z3.FPSort(15, 113)
    else:
        return z3.Float64()


@dataclass
class FloatConfig:
    """Configuration for floating-point analysis."""

    precision: FloatPrecision = FloatPrecision.DOUBLE
    rounding_mode: str = "RNE"
    check_nan: bool = True
    check_infinity: bool = True
    check_underflow: bool = True
    check_overflow: bool = True
    check_denormal: bool = False

    def get_rounding_mode(self) -> z3.FPRMRef:
        """Get Z3 rounding mode."""
        modes = {
            "RNE": z3.RNE(),
            "RNA": z3.RNA(),
            "RTP": z3.RTP(),
            "RTN": z3.RTN(),
            "RTZ": z3.RTZ(),
        }
        return modes.get(self.rounding_mode, z3.RNE())


class SymbolicFloat:
    """A symbolic floating-point value using Z3 FP theory.
    Supports:
    - Arithmetic operations (+, -, *, /)
    - Comparisons (<, <=, >, >=, ==, !=)
    - Special value checks (NaN, Inf, denormal)
    - Rounding mode awareness
    """

    _counter = 0

    def __init__(
        self,
        name: str | None = None,
        value: float | None = None,
        z3_expr: z3.FPRef | None = None,
        config: FloatConfig | None = None,
    ):
        self.config = config or FloatConfig()
        self._sort = get_fp_sort(self.config.precision)
        self._rm = self.config.get_rounding_mode()
        if z3_expr is not None:
            self._expr = z3_expr
            self.name = name or f"fp_{SymbolicFloat._counter}"
        elif value is not None:
            self._expr = z3.FPVal(value, self._sort)
            self.name = name or f"fp_const_{value}"
        else:
            SymbolicFloat._counter += 1
            self.name = name or f"fp_{SymbolicFloat._counter}"
            self._expr = z3.FP(self.name, self._sort)

    @property
    def z3_expr(self) -> z3.FPRef:
        """Get the underlying Z3 expression."""
        return self._expr

    def __add__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_expr = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpAdd(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __radd__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        return self.__add__(other)

    def __sub__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_expr = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpSub(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rsub__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpSub(self._rm, other_fp, self._expr),
            config=self.config,
        )

    def __mul__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_expr = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpMul(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rmul__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        return self.__mul__(other)

    def __truediv__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_expr = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpDiv(self._rm, self._expr, other_expr),
            config=self.config,
        )

    def __rtruediv__(self, other: SymbolicFloat | float) -> SymbolicFloat:
        other_fp = self._to_fp(other)
        return SymbolicFloat(
            z3_expr=z3.fpDiv(self._rm, other_fp, self._expr),
            config=self.config,
        )

    def __neg__(self) -> SymbolicFloat:
        return SymbolicFloat(
            z3_expr=z3.fpNeg(self._expr),
            config=self.config,
        )

    def __abs__(self) -> SymbolicFloat:
        return SymbolicFloat(
            z3_expr=z3.fpAbs(self._expr),
            config=self.config,
        )

    def __lt__(self, other: SymbolicFloat | float) -> z3.BoolRef:
        other_expr = self._to_fp(other)
        return z3.fpLT(self._expr, other_expr)

    def __le__(self, other: SymbolicFloat | float) -> z3.BoolRef:
        other_expr = self._to_fp(other)
        return z3.fpLEQ(self._expr, other_expr)

    def __gt__(self, other: SymbolicFloat | float) -> z3.BoolRef:
        other_expr = self._to_fp(other)
        return z3.fpGT(self._expr, other_expr)

    def __ge__(self, other: SymbolicFloat | float) -> z3.BoolRef:
        other_expr = self._to_fp(other)
        return z3.fpGEQ(self._expr, other_expr)

    def __eq__(self, other: object) -> z3.BoolRef:
        if isinstance(other, (SymbolicFloat, float, int)):
            other_expr = self._to_fp(other)
            return z3.fpEQ(self._expr, other_expr)
        return NotImplemented

    def __ne__(self, other: object) -> z3.BoolRef:
        if isinstance(other, (SymbolicFloat, float, int)):
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
        """Check if value is a normal (not special) number."""
        return z3.fpIsNormal(self._expr)

    def is_positive(self) -> z3.BoolRef:
        """Check if value is positive."""
        return z3.fpIsPositive(self._expr)

    def is_negative(self) -> z3.BoolRef:
        """Check if value is negative."""
        return z3.fpIsNegative(self._expr)

    def sqrt(self) -> SymbolicFloat:
        """Square root."""
        return SymbolicFloat(
            z3_expr=z3.fpSqrt(self._rm, self._expr),
            config=self.config,
        )

    def fma(self, mul: SymbolicFloat, add: SymbolicFloat) -> SymbolicFloat:
        """Fused multiply-add: self * mul + add."""
        return SymbolicFloat(
            z3_expr=z3.fpFMA(self._rm, self._expr, mul._expr, add._expr),
            config=self.config,
        )

    def min(self, other: SymbolicFloat) -> SymbolicFloat:
        """Minimum of two values."""
        return SymbolicFloat(
            z3_expr=z3.fpMin(self._expr, other._expr),
            config=self.config,
        )

    def max(self, other: SymbolicFloat) -> SymbolicFloat:
        """Maximum of two values."""
        return SymbolicFloat(
            z3_expr=z3.fpMax(self._expr, other._expr),
            config=self.config,
        )

    def to_int(self) -> z3.ArithRef:
        """Convert to integer (rounds toward zero)."""
        bv = z3.fpToSBV(z3.RTZ(), self._expr, z3.BitVecSort(64))
        return z3.BV2Int(bv, is_signed=True)

    def _to_fp(self, value: SymbolicFloat | float | int) -> z3.FPRef:
        """Convert value to FP expression."""
        if isinstance(value, SymbolicFloat):
            return value._expr
        elif isinstance(value, (int, float)):
            return z3.FPVal(float(value), self._sort)
        else:
            raise TypeError(f"Cannot convert {type(value)} to FP")

    def __repr__(self) -> str:
        return f"SymbolicFloat({self.name})"


class FloatAnalyzer:
    """Analyzer for floating-point issues."""

    def __init__(self, config: FloatConfig | None = None):
        self.config = config or FloatConfig()
        self._issues: list[dict[str, Any]] = []

    def check_operation(
        self,
        op: str,
        result: SymbolicFloat,
        operands: list[SymbolicFloat],
        constraints: list[z3.BoolRef],
    ) -> list[dict[str, Any]]:
        """Check a floating-point operation for issues."""
        issues = []
        from pyspectre.core.solver import get_model, is_satisfiable

        if self.config.check_nan:
            nan_check = constraints + [result.is_nan()]
            if is_satisfiable(nan_check):
                issues.append(
                    {
                        "type": "NaN_RESULT",
                        "message": f"Operation {op} may produce NaN",
                        "model": get_model(nan_check),
                    }
                )
        if self.config.check_infinity:
            inf_check = constraints + [result.is_infinity()]
            if is_satisfiable(inf_check):
                issues.append(
                    {
                        "type": "INFINITY_RESULT",
                        "message": f"Operation {op} may produce infinity",
                        "model": get_model(inf_check),
                    }
                )
        if op in ("div", "truediv", "/") and len(operands) >= 2:
            div_zero = constraints + [operands[1].is_zero()]
            if is_satisfiable(div_zero):
                issues.append(
                    {
                        "type": "FP_DIVISION_BY_ZERO",
                        "message": "Floating-point division by zero",
                        "model": get_model(div_zero),
                    }
                )
        if self.config.check_denormal:
            denorm_check = constraints + [result.is_denormal()]
            if is_satisfiable(denorm_check):
                issues.append(
                    {
                        "type": "DENORMAL_RESULT",
                        "message": f"Operation {op} may produce denormalized number",
                        "model": get_model(denorm_check),
                    }
                )
        self._issues.extend(issues)
        return issues

    def check_comparison(
        self,
        left: SymbolicFloat,
        right: SymbolicFloat,
        constraints: list[z3.BoolRef],
    ) -> list[dict[str, Any]]:
        """Check for comparison issues (NaN comparisons are always false)."""
        issues = []
        from pyspectre.core.solver import get_model, is_satisfiable

        nan_cmp = constraints + [z3.Or(left.is_nan(), right.is_nan())]
        if is_satisfiable(nan_cmp):
            issues.append(
                {
                    "type": "NAN_COMPARISON",
                    "message": "Comparing with NaN always returns False",
                    "model": get_model(nan_cmp),
                }
            )
        return issues

    def get_all_issues(self) -> list[dict[str, Any]]:
        """Get all detected issues."""
        return list(self._issues)


class AccuracyAnalyzer:
    """Analyzes numerical accuracy and error propagation."""

    def __init__(self, precision: FloatPrecision = FloatPrecision.DOUBLE):
        self.precision = precision
        self._sort = get_fp_sort(precision)
        if precision == FloatPrecision.SINGLE:
            self.epsilon = 2**-23
        else:
            self.epsilon = 2**-52

    def ulp_difference(
        self,
        computed: SymbolicFloat,
        exact: SymbolicFloat,
    ) -> z3.FPRef:
        """Compute ULP (Units in Last Place) difference."""
        diff = computed - exact
        return z3.fpAbs(diff.z3_expr)

    def relative_error(
        self,
        computed: SymbolicFloat,
        exact: SymbolicFloat,
    ) -> SymbolicFloat:
        """Compute relative error."""
        diff = computed - exact
        return SymbolicFloat(
            z3_expr=z3.fpDiv(
                z3.RNE(),
                z3.fpAbs(diff.z3_expr),
                z3.fpAbs(exact.z3_expr),
            ),
            config=computed.config,
        )

    def check_catastrophic_cancellation(
        self,
        a: SymbolicFloat,
        b: SymbolicFloat,
        result: SymbolicFloat,
        constraints: list[z3.BoolRef],
    ) -> bool:
        """Check for catastrophic cancellation in subtraction."""
        from pyspectre.core.solver import is_satisfiable

        sum_mag = z3.fpAdd(z3.RNE(), z3.fpAbs(a.z3_expr), z3.fpAbs(b.z3_expr))
        diff_mag = z3.fpAbs(result.z3_expr)
        ratio_check = constraints + [
            z3.fpLT(diff_mag, z3.fpMul(z3.RNE(), sum_mag, z3.FPVal(0.001, a._sort)))
        ]
        return is_satisfiable(ratio_check)


__all__ = [
    "FloatPrecision",
    "FloatConfig",
    "SymbolicFloat",
    "FloatAnalyzer",
    "AccuracyAnalyzer",
    "get_fp_sort",
]
