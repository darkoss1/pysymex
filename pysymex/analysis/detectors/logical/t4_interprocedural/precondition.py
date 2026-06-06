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

"""Precondition Impossibility logic rule.

This module implements the precondition impossibility logic rule (Tier 4), which detects
contradictions in constraints placed on function arguments, parameters, input variables,
or explicit preconditions.

Bug Class Detected:
    Logical contradiction (precondition impossibility).

Required Evidence:
    An unsatisfiable core containing inconsistent bounds or conflicting assignments on parameter/precondition variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    bounds_are_inconsistent,
    extract_bounds,
    extract_var_const_equalities,
)


class PreconditionImpossibilityRule(LogicRule):
    """Logic rule for detecting precondition impossibility.

    This rule checks the unsatisfiable core for inconsistent bounds or conflicting values
    on parameters or precondition-related variables, indicating that the function cannot be
    called under any valid inputs.

    Bug Class Detected:
        Logical contradiction (precondition impossibility).

    Required Evidence:
        ContradictionContext with conflicting constraints on function arguments or preconditions.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "Precondition Impossibility"
    tier = 4

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a precondition contradiction.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a precondition contradiction is detected, False otherwise.
        """
        bounds = extract_bounds(ctx.core)
        equalities = extract_var_const_equalities(ctx.core)

        for var, b in bounds.items():
            lname = var.lower()
            if (
                "arg" not in lname
                and "param" not in lname
                and "input" not in lname
                and "pre" not in lname
            ):
                continue
            if bounds_are_inconsistent(b):
                return True
            if var in equalities and len(equalities[var]) > 1:
                return True
        return False
