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

"""Self-contradiction logical contradiction rule.

Detects contradictions where a single assertion is inherently self-contradictory
independent of other path conditions (e.g. x != x).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import count_variables
import z3


class SelfContradictionRule(LogicRule):
    """Rule that matches self-contradictions such as a variable not equaling itself."""

    name = "Self-Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a self-contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains exactly one variable and one constraint, which is
            of the form Not(x == x), otherwise False.
        """
        if count_variables(ctx.core) != 1 or len(ctx.core) != 1:
            return False
        expr = ctx.core[0]
        if not z3.is_not(expr) or expr.num_args() != 1:
            return False
        inner = expr.arg(0)
        if not z3.is_app(inner) or inner.decl().kind() != z3.Z3_OP_EQ or inner.num_args() != 2:
            return False
        return bool(z3.eq(inner.arg(0), inner.arg(1)))
