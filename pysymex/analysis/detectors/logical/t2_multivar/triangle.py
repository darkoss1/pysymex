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
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator
import z3


class TriangleImpossibilityRule(LogicRule):
    name = "Triangle Impossibility"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 3 or len(ctx.core) < 3:
            return False

        has_gt = core_has_operator(ctx.core, {z3.Z3_OP_GT, z3.Z3_OP_GE})
        has_lt = core_has_operator(ctx.core, {z3.Z3_OP_LT, z3.Z3_OP_LE})
        has_not = core_has_operator(ctx.core, {z3.Z3_OP_NOT})

        return has_gt or has_lt or has_not
