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
from pysymex.analysis.detectors.logical.utils import count_variables, core_has_operator


class ParityContradictionRule(LogicRule):
    name = "Parity Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) != 1:
            return False
        if not core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM}):
            return False

        # Check if there is a modulo by 2
        for c in ctx.core:
            worklist: list[z3.ExprRef] = [c]
            seen = {c.get_id()}
            while worklist:
                node = worklist.pop()
                if z3.is_app(node) and node.decl().kind() in (z3.Z3_OP_MOD, z3.Z3_OP_REM):
                    if node.num_args() == 2:
                        arg1 = node.arg(1)
                        if z3.is_int_value(arg1):
                            try:
                                if arg1.as_long() == 2:
                                    return True
                            except Exception:
                                pass
                for child in node.children():
                    if child.get_id() not in seen:
                        seen.add(child.get_id())
                        worklist.append(child)
        return False
