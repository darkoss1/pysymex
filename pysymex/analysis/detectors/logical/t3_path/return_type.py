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


class ReturnTypeContradictionRule(LogicRule):
    name = "Return Type Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        names = get_variable_names_all(ctx.core)
        lower_names = {name.lower() for name in names}
        has_return_signal = any(
            "ret" in name or "return" in name or "result" in name for name in lower_names
        )
        if not has_return_signal:
            return False

        type_markers = {
            "_is_int": "int",
            "_is_bool": "bool",
            "_is_float": "float",
            "_is_str": "str",
            "_is_list": "list",
            "_is_tuple": "tuple",
            "_is_dict": "dict",
            "_is_none": "none",
        }
        flagged_types: set[str] = set()
        for name in lower_names:
            if "ret" not in name and "return" not in name and "result" not in name:
                continue
            for suffix, ty in type_markers.items():
                if suffix in name:
                    flagged_types.add(ty)

        if len(flagged_types) > 1:
            return True

        bool_assignments = extract_bool_assignments(ctx.core)
        for name, values in bool_assignments.items():
            lname = name.lower()
            if ("ret" in lname or "return" in lname or "result" in lname) and len(values) > 1:
                return True

        equalities = extract_var_const_equalities(ctx.core)
        for name, values in equalities.items():
            lname = name.lower()
            if ("ret" in lname or "return" in lname or "result" in lname) and len(values) > 1:
                return True

        return False
