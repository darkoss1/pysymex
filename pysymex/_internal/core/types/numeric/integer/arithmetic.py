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

"""Integer arithmetic slots for symbolic integers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.numeric.integer.core import IntCoreMixin
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class IntArithmeticMixin(IntCoreMixin):
    """Integer arithmetic slots, including existing symbolic-zero divisor masking."""

    def _to_z3_int(self, value: object) -> z3.ArithRef | None:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(value, SymbolicInt):
            return value.z3_int
        if isinstance(value, int) and not isinstance(value, bool):
            return ConstraintValues.int(value)
        return None

    def __add__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicFloat.from_int_expr(self.z3_int) + other
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicInt(self.z3_int + other_z3)

    def __radd__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        return self.__add__(other)

    def __sub__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicFloat.from_int_expr(self.z3_int) - other
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicInt(self.z3_int - other_z3)

    def __rsub__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, float)):
            return other - SymbolicFloat.from_int_expr(self.z3_int)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicInt(other_z3 - self.z3_int)

    def __mul__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicFloat.from_int_expr(self.z3_int) * other
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        return SymbolicInt(self.z3_int * other_z3)

    def __rmul__(
        self,
        other: SymbolicInt | SymbolicFloat | float,
    ) -> SymbolicInt | SymbolicFloat:
        return self.__mul__(other)

    def __neg__(self) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        return SymbolicInt(-self.z3_int)

    def __pos__(self) -> SymbolicInt:
        return cast("SymbolicInt", self)

    def __abs__(self) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        return SymbolicInt(z3.If(self.z3_int >= 0, self.z3_int, -self.z3_int))

    def __mod__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(other_z3, Z3_ZERO):
            msg = "integer modulo by zero"
            raise ZeroDivisionError(msg)
        safe_divisor = z3.If(other_z3 == 0, ConstraintValues.int(1), other_z3)
        return SymbolicInt(ScalarValueOps.py_mod(self.z3_int, safe_divisor))

    def __rmod__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(self.z3_int, Z3_ZERO):
            msg = "integer modulo by zero"
            raise ZeroDivisionError(msg)
        safe_divisor = z3.If(self.z3_int == 0, ConstraintValues.int(1), self.z3_int)
        return SymbolicInt(ScalarValueOps.py_mod(other_z3, safe_divisor))

    def __floordiv__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(other_z3, Z3_ZERO):
            msg = "integer division by zero"
            raise ZeroDivisionError(msg)
        safe_divisor = z3.If(other_z3 == 0, ConstraintValues.int(1), other_z3)
        return SymbolicInt(ScalarValueOps.py_floor_div(self.z3_int, safe_divisor))

    def __rfloordiv__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(self.z3_int, Z3_ZERO):
            msg = "integer division by zero"
            raise ZeroDivisionError(msg)
        safe_divisor = z3.If(self.z3_int == 0, ConstraintValues.int(1), self.z3_int)
        return SymbolicInt(ScalarValueOps.py_floor_div(other_z3, safe_divisor))

    def __truediv__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return SymbolicFloat.from_int_expr(self.z3_int) / other
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(other_z3, Z3_ZERO):
            msg = "division by zero"
            raise ZeroDivisionError(msg)
        safe_denom = z3.If(other_z3 == 0, ConstraintValues.int(1), other_z3)
        return SymbolicFloat.from_int_expr(self.z3_int) / SymbolicFloat.from_int_expr(safe_denom)

    def __rtruediv__(self, other: SymbolicInt | SymbolicFloat | float) -> SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        if isinstance(other, (SymbolicFloat, float)):
            return other / SymbolicFloat.from_int_expr(self.z3_int)
        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if z3.eq(self.z3_int, Z3_ZERO):
            msg = "division by zero"
            raise ZeroDivisionError(msg)
        safe_denom = z3.If(self.z3_int == 0, ConstraintValues.int(1), self.z3_int)
        return SymbolicFloat.from_int_expr(other_z3) / SymbolicFloat.from_int_expr(safe_denom)

    def __pow__(self, other: SymbolicInt | int) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if not z3.is_int_value(other_z3):
            return NotImplemented
        exponent = other_z3.as_long()
        if z3.is_int_value(self.z3_int):
            result = self.z3_int.as_long() ** exponent
            if isinstance(result, int):
                return SymbolicInt.concrete(result)
            return SymbolicFloat.concrete(result)
        if exponent >= 0:
            return SymbolicInt(z3.ToInt(self.z3_int**exponent))
        result = z3.fpToFP(
            z3.RNE(),
            z3.ToReal(self.z3_int) ** exponent,
            z3.Float64(),
        )
        return SymbolicFloat(z3_expr=z3.If(self.z3_int == 0, z3.fpNaN(z3.Float64()), result))

    def __rpow__(self, other: SymbolicInt | int) -> SymbolicInt | SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_z3 = self._to_z3_int(other)
        if other_z3 is None:
            return NotImplemented
        if not z3.is_int_value(self.z3_int):
            return NotImplemented
        exponent = self.z3_int.as_long()
        if z3.is_int_value(other_z3):
            result = other_z3.as_long() ** exponent
            if isinstance(result, int):
                return SymbolicInt.concrete(result)
            return SymbolicFloat.concrete(result)
        if exponent >= 0:
            return SymbolicInt(z3.ToInt(other_z3**exponent))
        result = z3.fpToFP(
            z3.RNE(),
            z3.ToReal(other_z3) ** exponent,
            z3.Float64(),
        )
        return SymbolicFloat(z3_expr=z3.If(other_z3 == 0, z3.fpNaN(z3.Float64()), result))
