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
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_const_equalities,
    get_variable_names_all,
)


class StateImpossibilityRule(LogicRule):
    name = "State Impossibility"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        state_names = [
            n
            for n in names
            if any(tag in n.lower() for tag in ("state", "status", "mode", "phase"))
        ]
        if not state_names:
            return False

        equalities = extract_var_const_equalities(ctx.core)
        for name in state_names:
            values = equalities.get(name)
            if values and len(values) > 1:
                return True

        bool_values = extract_bool_assignments(ctx.core)
        for name in state_names:
            values = bool_values.get(name)
            if values and len(values) > 1:
                return True

        return False
