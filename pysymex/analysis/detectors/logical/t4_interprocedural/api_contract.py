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

"""API Contract Violation logic rule.

This module implements the API contract violation logic rule (Tier 4), which detects
contradictions arising from conflicting constraints on variables associated with API
boundaries, parameters, return values, or explicitly named contracts.

Bug Class Detected:
    Logical contradiction (API contract violation).

Required Evidence:
    An unsatisfiable core containing contradicting constraints (e.g., conflicting equality,
    boolean assignments, or comparison relationships) on API-related variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_const_equalities,
    extract_var_var_comparisons,
    get_variable_names_all,
)


def _is_api_contract_name(name: str) -> bool:
    """Check if a variable name indicates it belongs to an API contract.

    Args:
        name (str): The name of the variable to check.

    Returns:
        bool: True if the name contains API contract tokens, False otherwise.
    """
    lname = name.lower()
    return any(
        token in lname for token in ("api", "contract", "pre", "post", "arg", "ret", "result")
    )


class ApiContractViolationRule(LogicRule):
    """Logic rule for detecting API contract violations.

    This rule checks the unsatisfiable core for contradictory constraints on variables
    associated with API boundaries, arguments, or returns.

    Bug Class Detected:
        Logical contradiction (API contract violation).

    Required Evidence:
        ContradictionContext showing contradictory constraints (such as conflicting constants,
        boolean values, or inconsistent comparison chains) on API-related variables.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "API Contract Violation"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains an API contract violation.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if an API contract contradiction is detected, False otherwise.
        """
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
            if not (_is_api_contract_name(a) and _is_api_contract_name(b)):
                continue
            if op == ">" and (b, ">=", a) in relation_set:
                return True
            if op == ">=" and (b, ">", a) in relation_set:
                return True
            if op == "==" and ((a, "!=", b) in relation_set or (b, "!=", a) in relation_set):
                return True

        return False
