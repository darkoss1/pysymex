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

"""Unary FP arithmetic and comparison slots for symbolic floats."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.numeric.floating.core import FloatCoreMixin, new_like

if TYPE_CHECKING:
    from types import NotImplementedType

    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class FloatUnaryComparisonMixin(FloatCoreMixin):
    """FP unary arithmetic and comparison operations."""

    def __neg__(self) -> SymbolicFloat:
        return new_like(self, z3.fpNeg(self._expr))

    def __pos__(self) -> SymbolicFloat:
        return cast("SymbolicFloat", self)

    def __abs__(self) -> SymbolicFloat:
        return new_like(self, z3.fpAbs(self._expr))

    def __lt__(self, other: SymbolicFloat | SymbolicInt | float) -> z3.BoolRef:
        return z3.fpLT(self._expr, self._to_fp(other))

    def __le__(self, other: SymbolicFloat | SymbolicInt | float) -> z3.BoolRef:
        return z3.fpLEQ(self._expr, self._to_fp(other))

    def __gt__(self, other: SymbolicFloat | SymbolicInt | float) -> z3.BoolRef:
        return z3.fpGT(self._expr, self._to_fp(other))

    def __ge__(self, other: SymbolicFloat | SymbolicInt | float) -> z3.BoolRef:
        return z3.fpGEQ(self._expr, self._to_fp(other))

    def _symbolic_eq(self, other: object) -> z3.BoolRef | NotImplementedType:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, SymbolicInt, float, int)):
            return z3.fpEQ(self._expr, self._to_fp(other))
        return NotImplemented

    def _symbolic_ne(self, other: object) -> z3.BoolRef | NotImplementedType:
        eq_result = self._symbolic_eq(other)
        if eq_result is NotImplemented:
            return NotImplemented
        return z3.Not(eq_result)

    if TYPE_CHECKING:

        def __eq__(self, other: object) -> bool: ...

        def __ne__(self, other: object) -> bool: ...

    else:

        def __eq__(self, other: object) -> z3.BoolRef | NotImplementedType:
            return self._symbolic_eq(other)

        def __ne__(self, other: object) -> z3.BoolRef | NotImplementedType:
            return self._symbolic_ne(other)
