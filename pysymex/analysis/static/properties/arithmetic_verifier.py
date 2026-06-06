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

"""Verify arithmetic safety properties (overflow, division-by-zero) via Z3."""

from __future__ import annotations

import z3

from pysymex.analysis.static.properties.solver_queries import check_violation_query
from pysymex.analysis.static.properties.types import PropertyKind, PropertyProof, PropertySpec
from pysymex.analysis.static.arithmetic.conditions import (
    divisor_zero_condition,
    expression_below_bound_condition,
    expression_outside_bounds_condition,
)
from pysymex.core.solver.engine.incremental import IncrementalSolver


class ArithmeticVerifier:
    """Verifies arithmetic properties and detects potential issues."""

    def __init__(self, int_bits: int = 64, timeout_ms: int = 5000) -> None:
        self.int_bits = int_bits
        self.int_min = -(2 ** (int_bits - 1))
        self.int_max = 2 ** (int_bits - 1) - 1
        self.timeout_ms = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)

    def _check_violation_condition(
        self,
        spec: PropertySpec,
        violation_condition: z3.BoolRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check whether a property-violation condition is satisfiable."""
        return check_violation_query(
            self.solver,
            spec,
            variables,
            lambda: (violation_condition,),
            constraints,
        )

    def check_overflow(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if expression can overflow."""
        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="No Overflow",
            description=f"Result within [{self.int_min}, {self.int_max}]",
        )
        return self._check_violation_condition(
            spec,
            expression_outside_bounds_condition(expr, self.int_min, self.int_max),
            variables,
            constraints,
        )

    def check_underflow(
        self,
        expr: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if expression can underflow (go below minimum)."""
        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="No Underflow",
            description=f"Result >= {self.int_min}",
        )
        return self._check_violation_condition(
            spec,
            expression_below_bound_condition(expr, self.int_min),
            variables,
            constraints,
        )

    def check_division_safe(
        self,
        dividend: z3.ExprRef,
        divisor: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if division is safe (divisor != 0)."""
        spec = PropertySpec(
            kind=PropertyKind.POSITIVE,
            name="Division Safety",
            description="divisor != 0",
        )
        _ = dividend
        return self._check_violation_condition(
            spec,
            divisor_zero_condition(divisor),
            variables,
            constraints,
        )

    def check_array_bounds(
        self,
        index: z3.ExprRef,
        length: z3.ExprRef,
        variables: dict[str, z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if array access is within bounds."""
        spec = PropertySpec(
            kind=PropertyKind.BOUNDED,
            name="Array Bounds",
            description="0 <= index < length",
        )
        index_int = z3.BV2Int(index, is_signed=True) if isinstance(index, z3.BitVecRef) else index
        length_int = (
            z3.BV2Int(length, is_signed=True) if isinstance(length, z3.BitVecRef) else length
        )
        return self._check_violation_condition(
            spec,
            z3.Or(index_int < 0, index_int >= length_int),
            variables,
            constraints,
        )
