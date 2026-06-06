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

"""Return type contradiction logical contradiction rule.

Detects contradictions where return or result variables are constrained to incompatible types
or conflicting concrete values along a path.
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_const_equalities,
    get_variable_names_all,
)
from pysymex.core.solver.engine.queries import check_sat_result


_TYPE_MARKERS = {
    "_is_int": "int",
    "_is_bool": "bool",
    "_is_float": "float",
    "_is_str": "str",
    "_is_list": "list",
    "_is_tuple": "tuple",
    "_is_dict": "dict",
    "_is_none": "none",
}


def _return_type_marker(name: str) -> tuple[str, str] | None:
    """Parse a variable name to check if it represents a return type indicator.

    Args:
        name: The variable name string.

    Returns:
        A tuple of (stem_name, type_suffix) if the variable is a return value type marker,
        otherwise None.
    """
    lname = name.lower()
    if "ret" not in lname and "return" not in lname and "result" not in lname:
        return None
    for suffix, ty in _TYPE_MARKERS.items():
        if lname.endswith(suffix):
            return (lname[: -len(suffix)], ty)
    return None


class ReturnTypeContradictionRule(LogicRule):
    """Rule that matches contradictions involving conflicting return/result types or values."""

    name = "Return Type Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a return type contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains return/result variables with conflicting type markers or values
            whose conjunction is unsatisfiable, otherwise False.
        """
        names = get_variable_names_all(ctx.core)
        lower_names = {name.lower() for name in names}
        has_return_signal = any(
            "ret" in name or "return" in name or "result" in name for name in lower_names
        )
        if not has_return_signal:
            return False

        bool_assignments = extract_bool_assignments(ctx.core)
        true_type_markers: dict[str, set[str]] = {}
        for name, values in bool_assignments.items():
            lname = name.lower()
            if ("ret" in lname or "return" in lname or "result" in lname) and len(values) > 1:
                return True
            if True not in values:
                continue
            marker = _return_type_marker(name)
            if marker is None:
                continue
            stem, ty = marker
            true_type_markers.setdefault(stem, set()).add(ty)

        if any(len(types) > 1 for types in true_type_markers.values()):
            return check_sat_result(ctx.core).is_unsat

        equalities = extract_var_const_equalities(ctx.core)
        for name, values in equalities.items():
            lname = name.lower()
            if ("ret" in lname or "return" in lname or "result" in lname) and len(values) > 1:
                return True

        return False
