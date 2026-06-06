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

"""Z3 real-sort numeric carrier used for approximate Python float operations."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val, get_real_val
from ..base import SymbolicType, TypeTag, fresh_name
from .bool import SymbolicBool
from .int import SymbolicInt


def _real_truthiness(expr: z3.ArithRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for fixed real-sort expressions."""
    if z3.is_int_value(expr):
        is_nonzero = expr.as_long() != 0
    elif z3.is_rational_value(expr):
        is_nonzero = expr.numerator_as_long() != 0
    else:
        if truthy:
            return expr != 0
        return expr == 0

    if truthy:
        return Z3_TRUE if is_nonzero else Z3_FALSE
    return Z3_FALSE if is_nonzero else Z3_TRUE


@dataclass
class SymbolicFloat(SymbolicType):
    """Float-labeled value represented by a Z3 ``Real`` expression.

    Limitations:
        This carrier models exact real arithmetic rather than IEEE-754
        rounding, NaN, infinities, signed zero, or overflow behavior. Use the
        FP-backed carrier when those distinctions are required.
    """

    z3_real: z3.ArithRef
    _name: str = field(default="")

    __hash__ = object.__hash__

    def hash_value(self) -> int:
        """Return the real-expression structural hash used in state summaries.

        Notes:
            This value is not a feasibility or semantic-equivalence proof.
        """
        return self.z3_real.hash()

    def __post_init__(self) -> None:
        """Assign a fresh float name when construction did not provide one."""
        if not self._name:
            self._name = fresh_name("float")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.FLOAT

    @property
    def is_float(self) -> z3.BoolRef:
        """Return the definite float-type marker for this carrier."""
        return Z3_TRUE

    @property
    def name(self) -> str:
        """Return the diagnostic name for this real-sort value."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 real expression represented by this carrier."""
        return self.z3_real

    def is_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented real is nonzero."""
        return _real_truthiness(self.z3_real, truthy=True)

    def is_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented real is zero."""
        return _real_truthiness(self.z3_real, truthy=False)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return modeled equality with real-valued floats or integers."""
        if isinstance(other, SymbolicFloat):
            return self.z3_real == other.z3_real
        elif isinstance(other, SymbolicInt):
            return self.z3_real == z3.ToReal(other.z3_int)
        return Z3_FALSE

    def __add__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return a real-sort sum expression, promoting integers as needed."""
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real + z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real + other.z3_real)

    def __radd__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return the commutative reflected real-sort sum expression."""
        return self.__add__(other)

    def __sub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return a real-sort difference expression."""
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real - z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real - other.z3_real)

    def __rsub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return the reflected real-sort difference expression."""
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(z3.ToReal(other.z3_int) - self.z3_real)
        return SymbolicFloat(other.z3_real - self.z3_real)

    def __mul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return a real-sort product expression."""
        if isinstance(other, SymbolicInt):
            return SymbolicFloat(self.z3_real * z3.ToReal(other.z3_int))
        return SymbolicFloat(self.z3_real * other.z3_real)

    def __rmul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return the commutative reflected real-sort product expression."""
        return self.__mul__(other)

    def __truediv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return real-sort division with a denominator-zero branch masked to one.

        Limitations:
            This method does not encode or emit Python division-by-zero
            exceptions; caller-side execution logic must retain that behavior.
        """
        if isinstance(other, SymbolicInt):
            denom = z3.ToReal(other.z3_int)
            safe_denom = z3.If(denom == 0, get_real_val(1), denom)
            return SymbolicFloat(self.z3_real / safe_denom)
        denom = other.z3_real
        safe_denom = z3.If(denom == 0, get_real_val(1), denom)
        return SymbolicFloat(self.z3_real / safe_denom)

    def __neg__(self) -> SymbolicFloat:
        """Return the arithmetic negation expression."""
        return SymbolicFloat(-self.z3_real)

    def __pos__(self) -> SymbolicFloat:
        """Return this carrier for unary plus."""
        return self

    def __abs__(self) -> SymbolicFloat:
        """Return an expression selecting the nonnegative magnitude."""
        return SymbolicFloat(z3.If(self.z3_real >= 0, self.z3_real, -self.z3_real))

    def __lt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled less-than predicate over real-sort expressions."""
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real < z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real < other.z3_real)

    def __le__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled less-than-or-equal predicate."""
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real <= z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real <= other.z3_real)

    def __gt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled greater-than predicate."""
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real > z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real > other.z3_real)

    def __ge__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled greater-than-or-equal predicate."""
        if isinstance(other, SymbolicInt):
            return SymbolicBool(self.z3_real >= z3.ToReal(other.z3_int))
        return SymbolicBool(self.z3_real >= other.z3_real)

    def __eq__(self, other: object) -> bool:
        """Return structural equality for supported real or integer carriers."""
        if isinstance(other, SymbolicFloat):
            return z3.eq(self.z3_real, other.z3_real)
        if isinstance(other, SymbolicInt):
            return z3.eq(self.z3_real, z3.ToReal(other.z3_int))
        return False

    def __ne__(self, other: object) -> bool:
        """Return the negation of supported structural equality."""
        return not self.__eq__(other)

    def __mod__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return real-sort modulo, producing zero on a zero-divisor branch.

        Limitations:
            Zero-divisor exception behavior is not expressed by this carrier.
        """
        if isinstance(other, SymbolicInt):
            other_real = z3.ToReal(other.z3_int)
        else:
            other_real = other.z3_real
        safe_divisor = z3.If(other_real == 0, get_real_val(1), other_real)
        floor_div = z3.ToInt(self.z3_real / safe_divisor)
        raw_res = self.z3_real - (z3.ToReal(floor_div) * safe_divisor)
        return SymbolicFloat(z3.If(other_real != 0, raw_res, get_real_val(0)))

    def __floordiv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return real-sort floor division, producing zero on a zero-divisor branch.

        Limitations:
            Zero-divisor exception behavior is not expressed by this carrier.
        """
        if isinstance(other, SymbolicInt):
            other_real = z3.ToReal(other.z3_int)
        else:
            other_real = other.z3_real
        safe_divisor = z3.If(other_real == 0, get_real_val(1), other_real)
        floor_div = z3.ToInt(self.z3_real / safe_divisor)
        return SymbolicFloat(z3.If(other_real != 0, z3.ToReal(floor_div), get_real_val(0)))

    def __pow__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return a real-sort exponentiation expression."""
        if isinstance(other, SymbolicInt):
            other_real = z3.ToReal(other.z3_int)
        else:
            other_real = other.z3_real
        return SymbolicFloat(self.z3_real**other_real)

    def to_int(self) -> SymbolicInt:
        """Convert represented finite real values by truncating toward zero.

        Z3 ``ToInt`` alone rounds toward negative infinity, so the expression
        applies it to the magnitude and restores the sign. Since this class
        has no NaN or infinity representation, those Python conversion paths
        are outside this method's model.
        """
        abs_floor = z3.ToInt(z3.If(self.z3_real >= 0, self.z3_real, -self.z3_real))
        sign = z3.If(self.z3_real < 0, get_int_val(-1), get_int_val(1))
        return SymbolicInt(abs_floor * sign)

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicFloat:
        """Create an unconstrained real-sort value labeled as a float."""
        name = name or fresh_name("float")
        return SymbolicFloat(z3.Real(name), name)

    @staticmethod
    def concrete(value: float) -> SymbolicFloat:
        """Create a real-sort value from a concrete Python float conversion."""
        return SymbolicFloat(get_real_val(value), str(value))
