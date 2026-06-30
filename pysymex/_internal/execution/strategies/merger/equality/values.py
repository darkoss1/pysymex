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

"""Symbolic value and constraint equality for state merging."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.state.types import HashableValue
from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue

logger = get_logger(__name__)


class ValueEqualityMixin(StateMergerMixinContract):
    """Compare symbolic values and path constraints structurally."""

    def _symbolic_values_equal(self, left: SymbolicValue, right: SymbolicValue) -> bool:
        """Check structural equality of SymbolicValue instances."""
        if bool(getattr(left, "_h_active", False)) != bool(getattr(right, "_h_active", False)):
            return False
        if getattr(left, "_modeled_object", None) is not getattr(right, "_modeled_object", None):
            return False
        if left.affinity_type != right.affinity_type:
            return False
        if left.min_val != right.min_val or left.max_val != right.max_val:
            return False

        if not z3.eq(left.z3_int, right.z3_int):
            return False
        if not z3.eq(left.is_int, right.is_int):
            return False
        if not z3.eq(left.z3_bool, right.z3_bool):
            return False
        if not z3.eq(left.is_bool, right.is_bool):
            return False
        if not z3.eq(left.z3_float, right.z3_float):
            return False
        if not z3.eq(left.is_float, right.is_float):
            return False
        if not z3.eq(left.z3_str, right.z3_str):
            return False
        if not z3.eq(left.is_str, right.is_str):
            return False
        if not z3.eq(left.z3_addr, right.z3_addr):
            return False
        if not z3.eq(left.is_obj, right.is_obj):
            return False
        if not z3.eq(left.is_path, right.is_path):
            return False
        if not z3.eq(left.is_none, right.is_none):
            return False
        if not z3.eq(left.is_list, right.is_list):
            return False
        if not z3.eq(left.is_dict, right.is_dict):
            return False
        if left.z3_array is None:
            if right.z3_array is not None:
                return False
        elif right.z3_array is None or not z3.eq(left.z3_array, right.z3_array):
            return False
        return True

    def values_structurally_equal(self, left: object, right: object) -> bool:
        """Best-effort structural equality without trusting hash collisions."""
        if left is right:
            return True
        if isinstance(left, z3.ExprRef):
            return isinstance(right, z3.ExprRef) and z3.eq(left, right)

        from pysymex._internal.core.types.scalars.values import SymbolicValue

        if isinstance(left, SymbolicValue):
            if not isinstance(right, SymbolicValue):
                return False
            if left.hash_value() != right.hash_value():
                return False
            return self._symbolic_values_equal(left, right)

        if isinstance(left, HashableValue) and isinstance(right, HashableValue):
            if left.hash_value() != right.hash_value():
                return False

        try:
            eq_result = left == right
        except (AttributeError, TypeError, RuntimeError) as exc:
            logger.debug("Symbolic value equality check failed: %s", exc)
            return False
        return eq_result

    def constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool:
        """Check if two constraints are equivalent."""
        if c1 is c2 or c1.hash() == c2.hash():
            return True
        try:
            return z3.eq(c1, c2)
        except z3.Z3Exception:
            return str(c1) == str(c2)
