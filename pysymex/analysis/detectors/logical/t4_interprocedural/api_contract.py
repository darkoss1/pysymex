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
    extract_var_var_comparisons,
    get_variable_names_all,
)


class ApiContractViolationRule(LogicRule):
    name = "API Contract Violation"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        lower_names = {n.lower() for n in names}

        has_api_signal = any(
            "api" in n or "contract" in n or "pre" in n or "post" in n for n in lower_names
        )
        if not has_api_signal:
            return False

        equalities = extract_var_const_equalities(ctx.core)
        for var, values in equalities.items():
            if len(values) > 1 and (
                "arg" in var.lower() or "ret" in var.lower() or "result" in var.lower()
            ):
                return True

        bool_values = extract_bool_assignments(ctx.core)
        for var, values in bool_values.items():
            if len(values) > 1 and ("contract" in var.lower() or "api" in var.lower()):
                return True

        relations = extract_var_var_comparisons(ctx.core)
        relation_set = {(a, op, b) for a, op, b in relations}
        for a, op, b in relations:
            if op == ">" and (b, ">=", a) in relation_set:
                return True
            if op == ">=" and (b, ">", a) in relation_set:
                return True
            if op == "==" and ((a, "!=", b) in relation_set or (b, "!=", a) in relation_set):
                return True

        return False
