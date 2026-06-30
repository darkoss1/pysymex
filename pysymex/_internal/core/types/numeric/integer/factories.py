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

"""Factory helpers for integer-backed symbolic values."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import fresh_name

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class IntFactoryMixin:
    """Construct integer-backed symbolic values."""

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        name = name or fresh_name("int")
        return SymbolicInt(z3.Int(name), name)

    @staticmethod
    def concrete(value: int) -> SymbolicInt:
        from pysymex._internal.core.types.numeric.int import SymbolicInt

        return SymbolicInt(ConstraintValues.int(value), str(value))
