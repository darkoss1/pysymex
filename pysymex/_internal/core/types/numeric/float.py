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

import z3

from pysymex._internal.config.solver.floats import FloatConfig, get_fp_sort
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.base import SymbolicType, TypeTag, fresh_name
from pysymex._internal.core.types.numeric.floating.advanced import FloatAdvancedOperationMixin
from pysymex._internal.core.types.numeric.floating.arithmetic import FloatBinaryArithmeticMixin
from pysymex._internal.core.types.numeric.floating.comparison import FloatUnaryComparisonMixin
from pysymex._internal.core.types.numeric.floating.conversions import FloatConversionMixin
from pysymex._internal.core.types.numeric.floating.factories import FloatFactoryMixin
from pysymex._internal.core.types.numeric.floating.predicates import FloatPredicateMixin


def _known_fp_truthiness(expr: z3.FPRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for fixed FP expressions."""
    if z3.is_fp_value(expr):
        is_nonzero = not expr.isZero()
        if truthy:
            return Z3_TRUE if is_nonzero else Z3_FALSE
        return Z3_FALSE if is_nonzero else Z3_TRUE
    if truthy:
        return z3.Not(z3.fpIsZero(expr))
    return z3.fpIsZero(expr)


class SymbolicFloat(
    FloatFactoryMixin,
    FloatConversionMixin,
    FloatAdvancedOperationMixin,
    FloatPredicateMixin,
    FloatUnaryComparisonMixin,
    FloatBinaryArithmeticMixin,
    SymbolicType,
):
    """Float value represented by Z3 FP theory.

    Arithmetic and conversions use the configured FP precision and rounding
    mode, retaining IEEE distinctions such as NaN, infinities, subnormals,
    and signed zero.

    Limitations:
        Operations create expressions only; they do not themselves test path
        feasibility or classify an exceptional floating-point result.
    """

    _counter = 0

    def __hash__(self) -> int:
        """Return object identity hash for mutable symbolic carriers."""
        return object.__hash__(self)

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
            self._name = name or fresh_name("float")
        elif value is not None:
            self._expr = z3.FPVal(value, self._sort)
            self._name = name or f"fp_const_{value}"
        else:
            SymbolicFloat._counter += 1
            self._name = name or f"fp_{SymbolicFloat._counter}"
            self._expr = z3.FP(self._name, self._sort)

    @property
    def type_tag(self) -> TypeTag:
        """Return the float type discriminator."""
        return TypeTag.FLOAT

    @property
    def is_float(self) -> z3.BoolRef:
        """Return the invariant that this carrier is a float."""
        return Z3_TRUE

    @property
    def name(self) -> str:
        """Return the diagnostic name for this FP value."""
        return self._name

    @property
    def z3_expr(self) -> z3.FPRef:
        """Return the underlying Z3 floating-point expression."""
        return self._expr

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 FP expression represented by this carrier."""
        return self._expr

    def is_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented FP value is nonzero."""
        return _known_fp_truthiness(self._expr, truthy=True)

    def is_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented FP value is zero."""
        return _known_fp_truthiness(self._expr, truthy=False)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return modeled equality with FP floats or integers."""
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, SymbolicInt)):
            return z3.fpEQ(self._expr, self._to_fp(other))
        return Z3_FALSE

    def __repr__(self) -> str:
        """Return the diagnostic representation for this FP carrier."""
        return f"SymbolicFloat({self.name})"
