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

"""Conversion, hashing, merging, and coercion helpers for symbolic floats."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.numeric.floating.core import FloatCoreMixin, new_like

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class FloatConversionMixin(FloatCoreMixin):
    """Conversion, hashing, merging, and operand coercion helpers."""

    def to_int(self) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        bv = z3.fpToSBV(z3.RTZ(), self._expr, z3.BitVecSort(64))
        return SymbolicInt(z3.BV2Int(bv, is_signed=True))

    def hash_value(self) -> int:
        return self._expr.hash()

    def conditional_merge(
        self,
        other: SymbolicFloat | SymbolicInt | float,
        condition: z3.BoolRef,
    ) -> SymbolicFloat:
        return new_like(self, z3.If(condition, self._expr, self._to_fp(other)))

    def _to_fp(self, value: SymbolicFloat | SymbolicInt | float) -> z3.FPRef:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(value, SymbolicFloat):
            if value._sort == self._sort:
                return value._expr
            return z3.fpToFP(self._rm, value._expr, self._sort)
        if isinstance(value, SymbolicInt):
            return z3.fpToFP(self._rm, z3.ToReal(value.z3_int), self._sort)
        return z3.FPVal(float(value), self._sort)
