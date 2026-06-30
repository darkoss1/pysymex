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

"""Shared storage contract for FP-backed symbolic float operation mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

    from pysymex._internal.config.solver.floats import FloatConfig
    from pysymex._internal.core.types.numeric.float import SymbolicFloat
    from pysymex._internal.core.types.numeric.int import SymbolicInt


class FloatCoreMixin:
    """Shared typed storage contract for symbolic float operation mixins."""

    config: FloatConfig
    _expr: z3.FPRef
    _rm: z3.FPRMRef
    _sort: z3.FPSortRef

    def _to_fp(self, value: SymbolicFloat | SymbolicInt | float) -> z3.FPRef:
        """Convert an operand into this instance's FP sort."""
        raise NotImplementedError


def new_like(owner: FloatCoreMixin, expr: z3.FPRef) -> SymbolicFloat:
    """Return a float carrier sharing the owner's FP configuration."""
    from pysymex._internal.core.types.numeric.float import SymbolicFloat

    return SymbolicFloat(z3_expr=expr, config=owner.config)
