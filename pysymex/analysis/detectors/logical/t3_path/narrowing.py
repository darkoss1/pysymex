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

"""Narrowing contradiction logical contradiction rule.

Detects contradictions arising from successive domain narrowing along a path, leading to
empty domains (e.g. x > 5, then x < 3, or x == 2 when x has been constrained to > 5).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_equalities,
)


class NarrowingContradictionRule(LogicRule):
    """Rule that matches contradictions resulting from inconsistent path domain narrowing."""

    name = "Narrowing Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a narrowing contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains at least 3 assertions and indicates inconsistent bounds,
            conflicting equalities, or equalities conflicting with bounds for any variable,
            otherwise False.
        """
        if len(ctx.core) < 3:
            return False

        bounds = extract_bounds(ctx.core)
        for b in bounds.values():
            if bounds_are_inconsistent(b):
                return True

        equalities = extract_var_const_equalities(ctx.core)
        for var, vals in equalities.items():
            if len(vals) > 1:
                return True
            b = bounds.get(var)
            if not b or not vals:
                continue
            value = next(iter(vals))
            min_val = b.get("min")
            max_val = b.get("max")
            min_strict = b.get("min_strict")
            max_strict = b.get("max_strict")
            if min_val is not None and value < int(min_val):
                return True
            if max_val is not None and value > int(max_val):
                return True
            if min_strict is not None and value <= int(min_strict):
                return True
            if max_strict is not None and value >= int(max_strict):
                return True

        return False
