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

"""Bounded bit-vector operations for symbolic integers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.numeric.integer.core import IntCoreMixin
from pysymex._internal.core.types.scalars.value.scalar_ops import ScalarValueOps

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class IntBitwiseMixin(IntCoreMixin):
    """Bounded 64-bit bit-vector operations converted back to integer sort."""

    def _to_bv(self, value: object) -> z3.BitVecRef | None:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(value, SymbolicInt):
            return value.as_bv
        if isinstance(value, int) and not isinstance(value, bool):
            return ScalarValueOps.int_to_bv(ConstraintValues.int(value))
        return None

    def _validate_shift_count(self, value: object) -> None:
        """Raise for a definitely negative shift count, matching Python."""
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        if isinstance(value, int) and not isinstance(value, bool):
            if value < 0:
                msg = "negative shift count"
                raise ValueError(msg)
            return
        if isinstance(value, SymbolicInt) and z3.is_int_value(value.z3_int):
            if value.z3_int.as_long() < 0:
                msg = "negative shift count"
                raise ValueError(msg)

    def __and__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(self.as_bv & other_bv))

    def __rand__(self, other: SymbolicInt | int) -> SymbolicInt:
        return self.__and__(other)

    def __or__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(self.as_bv | other_bv))

    def __ror__(self, other: SymbolicInt | int) -> SymbolicInt:
        return self.__or__(other)

    def __xor__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(self.as_bv ^ other_bv))

    def __rxor__(self, other: SymbolicInt | int) -> SymbolicInt:
        return self.__xor__(other)

    def __invert__(self) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        return SymbolicInt(ScalarValueOps.bv_to_int(~self.as_bv))

    def __lshift__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        self._validate_shift_count(other)
        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(self.as_bv << other_bv))

    def __rlshift__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        self._validate_shift_count(self)
        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(other_bv << self.as_bv))

    def __rshift__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        self._validate_shift_count(other)
        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(self.as_bv >> other_bv))

    def __rrshift__(self, other: SymbolicInt | int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        self._validate_shift_count(self)
        other_bv = self._to_bv(other)
        if other_bv is None:
            return NotImplemented
        return SymbolicInt(ScalarValueOps.bv_to_int(other_bv >> self.as_bv))
