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
from pysymex.analysis.detectors.logical.utils import core_has_operator
import z3


class SequentialModularRule(LogicRule):
    name = "Sequential Modular Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        has_mod = core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM})
        has_mul = core_has_operator(ctx.core, {z3.Z3_OP_MUL})
        # Sequential modular contradictions stem from arithmetic substitutions under modulo.
        return has_mod and has_mul
