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

"""Range contradiction logical contradiction rule.

Detects contradictions where bounds for a single variable are mathematically inconsistent
(e.g., x > 5 and x < 3).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    count_variables,
    extract_bounds,
)


class RangeContradictionRule(LogicRule):
    """Rule that matches contradictions involving a single variable and inconsistent ranges/bounds."""

    name = "Range Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a range contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains only 1 variable and that variable's extracted bounds
            are mathematically inconsistent, otherwise False.
        """
        if count_variables(ctx.core) != 1:
            return False
        return any(bounds_are_inconsistent(bounds) for bounds in extract_bounds(ctx.core).values())
