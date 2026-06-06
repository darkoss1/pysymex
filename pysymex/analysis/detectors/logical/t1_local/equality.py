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

"""Equality contradiction logical contradiction rule.

Detects contradictions where a single variable is restricted to conflicting concrete value
assignments (e.g. x == 1 and x == 2, or x == 1 and x != 1).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    core_has_operator,
    extract_var_const_disequalities,
    extract_var_const_equalities,
)


class EqualityContradictionRule(LogicRule):
    """Rule that matches contradictions involving a single variable and conflicting equalities/disequalities."""

    name = "Equality Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents an equality contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains only 1 variable, lacks arithmetic operators, and contains
            conflicting equalities or equalities contradicting disequalities, otherwise False.
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
        equalities = extract_var_const_equalities(ctx.core)
        disequalities = extract_var_const_disequalities(ctx.core)
        for var, values in equalities.items():
            if len(values) > 1:
                return True
            if values & disequalities.get(var, set()):
                return True
        return False
