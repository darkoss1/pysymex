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

"""Integer comparison slots for symbolic integers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.numeric.integer.core import IntCoreMixin

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.bool import SymbolicBool
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class IntComparisonMixin(IntCoreMixin):
    """Integer comparison slots with FP promotion when required."""

    def _to_z3_int(self, value: object) -> z3.ArithRef | None:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(value, SymbolicInt):
            return value.z3_int
        if isinstance(value, int) and not isinstance(value, bool):
            from pysymex._internal.core.solver.constraints.values import ConstraintValues

            return ConstraintValues.int(value)
        return None

    def __lt__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicBool:
        from pysymex._internal.core.types.numeric.bool import SymbolicBool
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicBool(SymbolicFloat.from_int_expr(self.z3_int) < other)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicBool(self.z3_int < other_z3)

    def __le__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicBool:
        from pysymex._internal.core.types.numeric.bool import SymbolicBool
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicBool(SymbolicFloat.from_int_expr(self.z3_int) <= other)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicBool(self.z3_int <= other_z3)

    def __gt__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicBool:
        from pysymex._internal.core.types.numeric.bool import SymbolicBool
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicBool(SymbolicFloat.from_int_expr(self.z3_int) > other)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicBool(self.z3_int > other_z3)

    def __ge__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicBool:
        from pysymex._internal.core.types.numeric.bool import SymbolicBool
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicBool(SymbolicFloat.from_int_expr(self.z3_int) >= other)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicBool(self.z3_int >= other_z3)

    def __eq__(self, other: object) -> bool:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, SymbolicInt):
            return z3.eq(self.z3_int, other.z3_int)
        if isinstance(other, SymbolicFloat):
            return z3.eq(SymbolicFloat.from_int_expr(self.z3_int).z3_expr, other.z3_expr)
        if isinstance(other, int) and not isinstance(other, bool):
            from pysymex._internal.core.solver.constraints.values import ConstraintValues

            return z3.eq(self.z3_int, ConstraintValues.int(other))
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)
