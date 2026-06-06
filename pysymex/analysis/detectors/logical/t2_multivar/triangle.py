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

"""Triangle impossibility logical contradiction rule.

Detects contradictions where assertions on the sum of multiple variables (e.g. x + y + z < 5)
contradict the individual variable bounds (e.g., x > 2, y > 2, z > 2).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    extract_bounds,
    extract_sum_const_comparisons,
    select_lower_bound,
    select_upper_bound,
)


class TriangleImpossibilityRule(LogicRule):
    """Rule that matches contradictions violating multi-variable bounding sum relationships."""

    name = "Triangle Impossibility"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a triangle impossibility.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains at least 3 variables and the sum of lower/upper bounds
            of variables violates the asserted sum comparison, otherwise False.
        """
        if count_variables(ctx.core) < 3 or len(ctx.core) < 3:
            return False
        bounds = extract_bounds(ctx.core)
        for names, op, value in extract_sum_const_comparisons(ctx.core):
            if len(set(names)) < 3:
                continue
            if op in ("<", "<="):
                lower_parts = [select_lower_bound(bounds[name]) for name in names if name in bounds]
                if len(lower_parts) != len(names) or any(part is None for part in lower_parts):
                    continue
                lower_sum = sum(part[0] for part in lower_parts if part is not None)
                strict = any(part[1] for part in lower_parts if part is not None)
                if lower_sum > value or (op == "<" and lower_sum == value):
                    return True
                if strict and lower_sum == value:
                    return True
            elif op in (">", ">="):
                upper_parts = [select_upper_bound(bounds[name]) for name in names if name in bounds]
                if len(upper_parts) != len(names) or any(part is None for part in upper_parts):
                    continue
                upper_sum = sum(part[0] for part in upper_parts if part is not None)
                strict = any(part[1] for part in upper_parts if part is not None)
                if upper_sum < value or (op == ">" and upper_sum == value):
                    return True
                if strict and upper_sum == value:
                    return True
        return False
