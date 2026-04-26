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
from pysymex.analysis.detectors.logical.utils import count_variables, extract_var_var_comparisons


class AntisymmetryRule(LogicRule):
    name = "Antisymmetry Violation"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        if count_variables(ctx.core) < 2:
            return False

        relations = extract_var_var_comparisons(ctx.core)
        if not relations:
            return False

        rel = {(a, op, b) for a, op, b in relations}
        for a, op, b in relations:
            if op == ">" and ((b, ">", a) in rel or (b, ">=", a) in rel):
                return True
            if op == ">=" and (b, ">", a) in rel:
                return True
            if op == "<" and ((b, "<", a) in rel or (b, "<=", a) in rel):
                return True
            if op == "<=" and (b, "<", a) in rel:
                return True
            if op == "==" and ((a, "!=", b) in rel or (b, "!=", a) in rel):
                return True

        return False
