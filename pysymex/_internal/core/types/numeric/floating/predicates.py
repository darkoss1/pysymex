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

"""IEEE FP classification predicates for symbolic floats."""

from __future__ import annotations

import z3

from pysymex._internal.core.types.numeric.floating.core import FloatCoreMixin


class FloatPredicateMixin(FloatCoreMixin):
    """IEEE FP classification predicates."""

    def is_nan(self) -> z3.BoolRef:
        return z3.fpIsNaN(self._expr)

    def is_infinity(self) -> z3.BoolRef:
        return z3.fpIsInf(self._expr)

    def is_positive_infinity(self) -> z3.BoolRef:
        return z3.And(z3.fpIsInf(self._expr), z3.fpIsPositive(self._expr))

    def is_negative_infinity(self) -> z3.BoolRef:
        return z3.And(z3.fpIsInf(self._expr), z3.fpIsNegative(self._expr))

    def is_zero(self) -> z3.BoolRef:
        return z3.fpIsZero(self._expr)

    def is_positive_zero(self) -> z3.BoolRef:
        return z3.And(z3.fpIsZero(self._expr), z3.fpIsPositive(self._expr))

    def is_negative_zero(self) -> z3.BoolRef:
        return z3.And(z3.fpIsZero(self._expr), z3.fpIsNegative(self._expr))

    def is_denormal(self) -> z3.BoolRef:
        return z3.fpIsSubnormal(self._expr)

    def is_normal(self) -> z3.BoolRef:
        return z3.fpIsNormal(self._expr)

    def is_positive(self) -> z3.BoolRef:
        return z3.fpIsPositive(self._expr)

    def is_negative(self) -> z3.BoolRef:
        return z3.fpIsNegative(self._expr)
