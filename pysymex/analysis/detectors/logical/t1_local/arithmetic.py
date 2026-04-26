# pysymex: Python Symbolic Execution & Formal Verification
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

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    core_has_operator,
)


class ArithmeticImpossibilityRule(LogicRule):
    name = "Arithmetic Impossibility"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1:
            return False
        has_arith = core_has_operator(
            ctx.core, {z3.Z3_OP_ADD, z3.Z3_OP_MUL, z3.Z3_OP_SUB, z3.Z3_OP_DIV, z3.Z3_OP_IDIV}
        )
        has_eq = core_has_operator(ctx.core, {z3.Z3_OP_EQ})
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        return has_arith and has_eq and not has_mod
