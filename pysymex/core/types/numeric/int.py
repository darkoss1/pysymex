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

"""Z3 integer-backed symbolic value with bounded bit-vector operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val, get_real_val
from ..base import SymbolicType, TypeTag, fresh_name
from .bool import SymbolicBool
from pysymex.core.types.scalars.values import bv_to_int, int_to_bv, py_floor_div, py_mod

if TYPE_CHECKING:
    from .float import SymbolicFloat


def _int_truthiness(expr: z3.ArithRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for fixed integer expressions."""
    if z3.is_int_value(expr):
        is_nonzero = expr.as_long() != 0
        if truthy:
            return Z3_TRUE if is_nonzero else Z3_FALSE
        return Z3_FALSE if is_nonzero else Z3_TRUE
    if truthy:
        return expr != 0
    return expr == 0


@dataclass
class SymbolicInt(SymbolicType):
    """Integer value represented primarily by a Z3 ``Int`` expression.

    Arithmetic remains unbounded in the integer sort. Bitwise operations
    convert through a cached 64-bit two's-complement view and therefore do
    not model Python's arbitrary-width bitwise semantics for all values.
    """

    z3_int: z3.ArithRef
    _name: str = field(default="")
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    __hash__ = object.__hash__

    def hash_value(self) -> int:
        """Return a structural hash of integer and cached bit-vector expressions.

        Notes:
            If materialized, the 64-bit cache is part of this summary because
            it records an additional representation. The hash is not a
            feasibility or semantic-equivalence proof.
        """
        h = self.z3_int.hash()
        if self._bv_cache is not None:
            h = (h * 31) ^ self._bv_cache.hash()
        return h

    def __post_init__(self) -> None:
        """Assign a fresh integer name when construction did not provide one."""
        if not self._name:
            self._name = fresh_name("int")

    @property
    def type_tag(self) -> TypeTag:
        """Property returning the type_tag."""
        return TypeTag.INT

    @property
    def is_int(self) -> z3.BoolRef:
        """Return the definite integer-type marker for this carrier."""
        return Z3_TRUE

    @property
    def name(self) -> str:
        """Return the diagnostic name for this symbolic integer."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Return the Z3 integer expression represented by this carrier."""
        return self.z3_int

    @property
    def value(self) -> z3.ArithRef:
        """Expose the underlying Z3 integer expression."""
        return self.z3_int

    @property
    def as_bv(self) -> z3.BitVecRef:
        """Return the cached 64-bit bit-vector encoding used by bitwise operators."""
        if self._bv_cache is None:
            self._bv_cache = int_to_bv(self.z3_int)
        return self._bv_cache

    def is_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented integer is nonzero."""
        return _int_truthiness(self.z3_int, truthy=True)

    def is_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented integer is zero."""
        return _int_truthiness(self.z3_int, truthy=False)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return modeled equality with integer, Boolean, or real-valued floats."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicInt):
            return self.z3_int == other.z3_int
        elif isinstance(other, SymbolicBool):
            return z3.If(other.z3_bool, self.z3_int == 1, self.z3_int == 0)
        elif isinstance(other, SymbolicFloat):
            return z3.ToReal(self.z3_int) == other.z3_real
        return Z3_FALSE

    def __add__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        """Return the integer or promoted real-sort sum expression."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) + other.z3_real)
        return SymbolicInt(self.z3_int + other.z3_int)

    def __radd__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        """Return the commutative reflected sum expression."""
        return self.__add__(other)

    def __sub__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        """Return the integer or promoted real-sort difference expression."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) - other.z3_real)
        return SymbolicInt(self.z3_int - other.z3_int)

    def __rsub__(self, other: SymbolicInt) -> SymbolicInt:
        """Return the reflected integer difference expression."""
        return SymbolicInt(other.z3_int - self.z3_int)

    def __mul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        """Return the integer or promoted real-sort product expression."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicFloat(z3.ToReal(self.z3_int) * other.z3_real)
        return SymbolicInt(self.z3_int * other.z3_int)

    def __rmul__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicInt | SymbolicFloat:
        """Return the commutative reflected product expression."""
        return self.__mul__(other)

    def __neg__(self) -> SymbolicInt:
        """Return the arithmetic negation expression."""
        return SymbolicInt(-self.z3_int)

    def __pos__(self) -> SymbolicInt:
        """Return this carrier for unary plus."""
        return self

    def __abs__(self) -> SymbolicInt:
        """Return an expression selecting the nonnegative magnitude."""
        return SymbolicInt(z3.If(self.z3_int >= 0, self.z3_int, -self.z3_int))

    def __mod__(self, other: SymbolicInt) -> SymbolicInt:
        """Return Python-style modulo for nonzero divisors in the encoded expression.

        Limitations:
            A concrete zero divisor raises immediately. A symbolic divisor is
            replaced by ``1`` on its zero branch; callers must separately
            preserve division-by-zero error semantics.
        """
        divisor = other.z3_int
        if z3.is_int_value(divisor) and divisor.as_long() == 0:
            raise ZeroDivisionError("integer modulo by zero")
        safe_divisor = z3.If(divisor == 0, get_int_val(1), divisor)
        return SymbolicInt(py_mod(self.z3_int, safe_divisor))

    def __floordiv__(self, other: SymbolicInt) -> SymbolicInt:
        """Return Python-style floor division with a masked symbolic-zero branch.

        Limitations:
            A concrete zero divisor raises immediately. A symbolic divisor is
            replaced by ``1`` on its zero branch; callers must separately
            preserve division-by-zero error semantics.
        """
        divisor = other.z3_int
        if z3.is_int_value(divisor) and divisor.as_long() == 0:
            raise ZeroDivisionError("integer division by zero")
        safe_divisor = z3.If(divisor == 0, get_int_val(1), divisor)
        return SymbolicInt(py_floor_div(self.z3_int, safe_divisor))

    def __truediv__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicFloat:
        """Return real-sort division with symbolic zero denominators masked to one.

        Limitations:
            Integer division by a concrete zero raises here. Symbolic integer
            or float zero denominators are not reported by this value method;
            their zero branch evaluates using denominator ``1``.
        """
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            denom = other.z3_real
            safe_denom = z3.If(denom == 0, get_real_val(1), denom)
            return SymbolicFloat(z3.ToReal(self.z3_int) / safe_denom)
        denom_int = other.z3_int
        if z3.is_int_value(denom_int) and denom_int.as_long() == 0:
            raise ZeroDivisionError("division by zero")
        denom = z3.ToReal(denom_int)
        safe_denom = z3.If(denom == 0, get_real_val(1), denom)
        return SymbolicFloat(z3.ToReal(self.z3_int) / safe_denom)

    def __pow__(self, other: SymbolicInt) -> SymbolicInt:
        """Return the Z3 integer-power expression."""
        return SymbolicInt(self.z3_int**other.z3_int)

    def __lt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled less-than predicate, promoting to reals as needed."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) < other.z3_real)
        return SymbolicBool(self.z3_int < other.z3_int)

    def __le__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled less-than-or-equal predicate."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) <= other.z3_real)
        return SymbolicBool(self.z3_int <= other.z3_int)

    def __gt__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled greater-than predicate."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) > other.z3_real)
        return SymbolicBool(self.z3_int > other.z3_int)

    def __ge__(self, other: SymbolicInt | SymbolicFloat) -> SymbolicBool:
        """Return a modeled greater-than-or-equal predicate."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicFloat):
            return SymbolicBool(z3.ToReal(self.z3_int) >= other.z3_real)
        return SymbolicBool(self.z3_int >= other.z3_int)

    def __eq__(self, other: object) -> bool:
        """Return structural equality for supported integer or real carriers."""
        from .float import SymbolicFloat

        if isinstance(other, SymbolicInt):
            return z3.eq(self.z3_int, other.z3_int)
        if isinstance(other, SymbolicFloat):
            return z3.eq(z3.ToReal(self.z3_int), other.z3_real)
        return False

    def __ne__(self, other: object) -> bool:
        """Return the negation of supported structural equality."""
        return not self.__eq__(other)

    def __and__(self, other: SymbolicInt) -> SymbolicInt:
        """Return bounded 64-bit bit-vector AND converted back to an integer."""
        bv_result = self.as_bv & other.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    def __or__(self, other: SymbolicInt) -> SymbolicInt:
        """Return bounded 64-bit bit-vector OR converted back to an integer."""
        bv_result = self.as_bv | other.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    def __xor__(self, other: SymbolicInt) -> SymbolicInt:
        """Return bounded 64-bit bit-vector XOR converted back to an integer."""
        bv_result = self.as_bv ^ other.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    def __invert__(self) -> SymbolicInt:
        """Return bounded 64-bit bit-vector inversion converted to an integer."""
        bv_result = ~self.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    def __lshift__(self, other: SymbolicInt) -> SymbolicInt:
        """Return a bounded 64-bit left-shift expression."""
        bv_result = self.as_bv << other.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    def __rshift__(self, other: SymbolicInt) -> SymbolicInt:
        """Return a bounded 64-bit arithmetic right-shift expression."""
        bv_result = self.as_bv >> other.as_bv
        return SymbolicInt(bv_to_int(bv_result))

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicInt:
        """Create an unconstrained symbolic integer expression."""
        name = name or fresh_name("int")
        return SymbolicInt(z3.Int(name), name)

    @staticmethod
    def concrete(value: int) -> SymbolicInt:
        """Create an integer value from a concrete Python ``int``."""
        return SymbolicInt(get_int_val(value), str(value))
