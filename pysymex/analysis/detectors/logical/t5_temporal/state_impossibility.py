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

"""State Impossibility logic rule.

This module implements the state impossibility logic rule (Tier 5), which detects
contradictions in variables representing state machines, mode, status, or phase attributes.

Bug Class Detected:
    Logical contradiction (state impossibility).

Required Evidence:
    An unsatisfiable core containing conflicting constant or boolean assignments on state-related variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_const_equalities,
    get_variable_names_all,
)


class StateImpossibilityRule(LogicRule):
    """Logic rule for detecting state impossibility contradictions.

    This rule checks the unsatisfiable core for conflicting constant or boolean assignments on variables
    representing states, status values, modes, or phases.

    Bug Class Detected:
        Logical contradiction (state impossibility).

    Required Evidence:
        ContradictionContext with multiple conflicting values assigned to the same state variable.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "State Impossibility"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a state impossibility contradiction.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a state contradiction is detected, False otherwise.
        """
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
