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

"""Numeric Range Propagation Contradiction logic rule.

This module implements the numeric range propagation rule (Tier 4), which detects
contradictions when propagating ranges across interprocedural boundary variables (arguments,
returns, etc.) leads to inconsistent bounds or contradictory comparisons.

Bug Class Detected:
    Logical contradiction (numeric range propagation contradiction).

Required Evidence:
    An unsatisfiable core containing inconsistent bounds or contradictory comparison relationships
    between interprocedural variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    count_variables,
    extract_bounds,
    extract_var_const_equalities,
    extract_var_var_comparisons,
    get_variable_names_all,
)


def _is_interprocedural_name(name: str) -> bool:
    """Check if a variable name indicates it participates in interprocedural interfaces.

    Args:
        name (str): The name of the variable to check.

    Returns:
        bool: True if the name contains interprocedural tokens, False otherwise.
    """
    lname = name.lower()
    return any(
        token in lname
        for token in (
            "arg",
            "param",
            "input",
            "ret",
            "result",
            "caller",
            "callee",
            "api",
            "contract",
        )
    )


class NumericRangePropagationRule(LogicRule):
    """Logic rule for detecting numeric range propagation contradictions.

    This rule checks the unsatisfiable core for inconsistent bounds or conflicting comparisons
    between interprocedural variables (e.g., `arg1 < arg2` and `arg2 < arg1`).

    Bug Class Detected:
        Logical contradiction (numeric range propagation contradiction).

    Required Evidence:
        ContradictionContext showing inconsistent bounds or conflicting relation sets on interprocedural variables.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "Numeric Range Propagation Contradiction"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a range propagation contradiction.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a range propagation contradiction is detected, False otherwise.
        """
        if len(ctx.core) < 2 or count_variables(ctx.core) < 2:
            return False

        names = {n.lower() for n in get_variable_names_all(ctx.core)}
        has_interproc_signal = any(
            token in name
            for name in names
            for token in (
                "arg",
                "param",
                "input",
                "ret",
                "result",
                "caller",
                "callee",
                "api",
                "contract",
            )
        )
        if not has_interproc_signal:
            return False

        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)
        for var, b in bounds.items():
            if bounds_are_inconsistent(b):
                return True
            if var in equalities and len(equalities[var]) > 1:
                return True

        relations = extract_var_var_comparisons(ctx.core)
        rel = {(a, op, b) for a, op, b in relations}

        for a, op, b in relations:
            if not (_is_interprocedural_name(a) and _is_interprocedural_name(b)):
                continue
            if op == "<" and ((b, "<", a) in rel or (b, "<=", a) in rel):
                return True
            if op == "<=" and (b, "<", a) in rel:
                return True
            if op == ">" and ((b, ">", a) in rel or (b, ">=", a) in rel):
                return True
            if op == ">=" and (b, ">", a) in rel:
                return True
            if op == "==" and ((a, "!=", b) in rel or (b, "!=", a) in rel):
                return True

        return False
