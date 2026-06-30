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

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicType, TypeTag, fresh_name
from pysymex._internal.core.types.numeric.bool import SymbolicBool
from pysymex._internal.core.types.numeric.integer.arithmetic import IntArithmeticMixin
from pysymex._internal.core.types.numeric.integer.bitwise import IntBitwiseMixin
from pysymex._internal.core.types.numeric.integer.comparison import IntComparisonMixin
from pysymex._internal.core.types.numeric.integer.factories import IntFactoryMixin
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps


def _int_truthiness(expr: z3.ArithRef, *, truthy: bool) -> z3.BoolRef:
    """Return literal truthiness for fixed integer expressions."""
    if z3.eq(expr, Z3_ZERO):
        return Z3_FALSE if truthy else Z3_TRUE
    if z3.is_int_value(expr):
        return Z3_TRUE if truthy else Z3_FALSE
    if truthy:
        return expr != 0
    return expr == 0


@dataclass(eq=False)
class SymbolicInt(
    IntFactoryMixin,
    IntBitwiseMixin,
    IntComparisonMixin,
    IntArithmeticMixin,
    SymbolicType,
):
    """Integer value represented primarily by a Z3 ``Int`` expression.

    Arithmetic remains unbounded in the integer sort. Bitwise operations
    convert through a cached 64-bit two's-complement view and therefore do
    not model Python's arbitrary-width bitwise semantics for all values.
    """

    z3_int: z3.ArithRef
    _name: str = field(default="")
    _bv_cache: z3.BitVecRef | None = field(default=None, init=False, repr=False, compare=False)

    def __hash__(self) -> int:
        """Return object identity hash for mutable symbolic carriers."""
        return object.__hash__(self)

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
            self._bv_cache = ScalarValueOps.int_to_bv(self.z3_int)
        return self._bv_cache

    def is_truthy(self) -> z3.BoolRef:
        """Return the predicate that the represented integer is nonzero."""
        return _int_truthiness(self.z3_int, truthy=True)

    def is_falsy(self) -> z3.BoolRef:
        """Return the predicate that the represented integer is zero."""
        return _int_truthiness(self.z3_int, truthy=False)

    def symbolic_eq(self, other: SymbolicType) -> z3.BoolRef:
        """Return modeled equality with integer, Boolean, or FP-backed floats."""
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, SymbolicInt):
            return self.z3_int == other.z3_int
        if isinstance(other, SymbolicBool):
            return z3.If(other.z3_bool, self.z3_int == 1, self.z3_int == 0)
        if isinstance(other, SymbolicFloat):
            return other.symbolic_eq(self)
        return Z3_FALSE
