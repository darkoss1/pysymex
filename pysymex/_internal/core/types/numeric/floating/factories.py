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

"""Factory helpers for FP-backed symbolic floats."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.config.solver.floats import FloatConfig, get_fp_sort
from pysymex._internal.core.types.base import fresh_name

if TYPE_CHECKING:
    from pysymex._internal.core.types.numeric.float import SymbolicFloat


class FloatFactoryMixin:
    """Construct FP-backed symbolic float values."""

    @staticmethod
    def from_int_expr(
        expr: z3.ArithRef,
        name: str | None = None,
        config: FloatConfig | None = None,
    ) -> SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        config = config or FloatConfig()
        sort = get_fp_sort(config.precision)
        z3_expr = z3.fpToFP(config.get_rounding_mode(), z3.ToReal(expr), sort)
        return SymbolicFloat(name=name, z3_expr=z3_expr, config=config)

    @staticmethod
    def symbolic(name: str | None = None) -> SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        return SymbolicFloat(name or fresh_name("float"))

    @staticmethod
    def concrete(value: float) -> SymbolicFloat:
        from pysymex._internal.core.types.numeric.float import SymbolicFloat

        return SymbolicFloat(value=value)
