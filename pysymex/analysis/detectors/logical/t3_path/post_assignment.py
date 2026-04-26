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
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_disequalities,
    extract_var_const_equalities,
)


class PostAssignmentContradictionRule(LogicRule):
    name = "Post-assignment Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        if len(ctx.core) < 2:
            return False

        equalities = extract_var_const_equalities(ctx.core)
        disequalities = extract_var_const_disequalities(ctx.core)
        bounds = extract_bounds(ctx.core)

        for var, values in equalities.items():
            if len(values) != 1:
                continue

            assigned = next(iter(values))
            if assigned in disequalities.get(var, set()):
                return True

            vbounds = bounds.get(var)
            if vbounds is None:
                continue
            if bounds_are_inconsistent(vbounds):
                return True

            min_val = vbounds.get("min")
            max_val = vbounds.get("max")
            min_strict = vbounds.get("min_strict")
            max_strict = vbounds.get("max_strict")

            if min_val is not None and assigned < int(min_val):
                return True
            if max_val is not None and assigned > int(max_val):
                return True
            if min_strict is not None and assigned <= int(min_strict):
                return True
            if max_strict is not None and assigned >= int(max_strict):
                return True

        return False
