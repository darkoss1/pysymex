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

"""Selected non-slot FP operations for symbolic floats."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.numeric.floating.core import FloatCoreMixin, new_like

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.float import SymbolicFloat


class FloatAdvancedOperationMixin(FloatCoreMixin):
    """Selected Z3 FP operations beyond Python's core arithmetic slots."""

    def sqrt(self) -> SymbolicFloat:
        return new_like(self, z3.fpSqrt(self._rm, self._expr))

    def fma(self, mul: SymbolicFloat, add: SymbolicFloat) -> SymbolicFloat:
        return new_like(self, z3.fpFMA(self._rm, self._expr, mul.z3_expr, add.z3_expr))

    def min(self, other: SymbolicFloat) -> SymbolicFloat:
        return new_like(self, z3.fpMin(self._expr, other.z3_expr))

    def max(self, other: SymbolicFloat) -> SymbolicFloat:
        return new_like(self, z3.fpMax(self._expr, other.z3_expr))
