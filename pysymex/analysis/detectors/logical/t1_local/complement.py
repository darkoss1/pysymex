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

"""Complement contradiction logical contradiction rule.

Detects contradictions where a single boolean variable is assigned opposing values (e.g. x and Not(x)).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    core_has_operator,
    extract_bool_assignments,
)


class ComplementContradictionRule(LogicRule):
    """Rule that matches contradictions involving a single variable and opposing boolean assignments."""

    name = "Complement Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a complement contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains only 1 variable, lacks arithmetic operators, and contains
            conflicting assignments for the variable, otherwise False.
        """
        if count_variables(ctx.core) != 1:
            return False
        if core_has_operator(
            ctx.core,
            {
                z3.Z3_OP_MOD,
                z3.Z3_OP_REM,
                z3.Z3_OP_ADD,
                z3.Z3_OP_MUL,
                z3.Z3_OP_SUB,
                z3.Z3_OP_DIV,
                z3.Z3_OP_IDIV,
            },
        ):
            return False
        return any(len(values) > 1 for values in extract_bool_assignments(ctx.core).values())
