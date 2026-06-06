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

"""Arithmetic impossibility logical contradiction rule.

Detects arithmetic contradictions that are unsat over integers but sat over reals.
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.core.solver.engine.queries import check_sat_result
from pysymex.analysis.detectors.logical.utils import (
    check_sat_over_reals_result,
    count_variables,
    core_has_operator,
)


class ArithmeticImpossibilityRule(LogicRule):
    """Rule that matches arithmetic contradictions that are impossible over integers.

    Typically detects contradictions involving single-variable integer arithmetic
    relationships that would be satisfiable if the variable were real (e.g. 2 * x == 1).
    """

    name = "Arithmetic Impossibility"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents an arithmetic impossibility.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains arithmetic operators, equality, no modulo operators,
            concerns a single variable, is unsat, but is sat over reals.
        """
        if count_variables(ctx.core) != 1:
            return False
        has_arith = core_has_operator(
            ctx.core, {z3.Z3_OP_ADD, z3.Z3_OP_MUL, z3.Z3_OP_SUB, z3.Z3_OP_DIV, z3.Z3_OP_IDIV}
        )
        has_eq = core_has_operator(ctx.core, {z3.Z3_OP_EQ})
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        if not (has_arith and has_eq and not has_mod):
            return False
        integer_result = check_sat_result(ctx.core)
        if not integer_result.is_unsat:
            return False
        return check_sat_over_reals_result(ctx.core).is_sat
