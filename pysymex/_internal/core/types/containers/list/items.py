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

"""Integer-channel storage helpers for concrete-backed symbolic lists."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.storage_ops import ContainerStorageOps
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    import z3


def const_item_expr(value: object, list_name: str) -> z3.ArithRef:
    """Return the integer-channel storage expression for a retained concrete item."""
    if isinstance(value, SymbolicValue):
        return ContainerStorageOps.storage_int_expr(value.z3_int, f"{list_name}_elem")
    if isinstance(value, bool):
        return ConstraintValues.int(int(value))
    if isinstance(value, int):
        return ConstraintValues.int(value)
    return Z3_ZERO
