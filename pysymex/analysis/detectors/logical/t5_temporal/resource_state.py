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

"""Resource State Contradiction logic rule.

This module implements the resource state contradiction logic rule (Tier 5), which detects
contradictions in constraints representing the state of files, sockets, handles, streams, or locks.

Bug Class Detected:
    Logical contradiction (resource state contradiction).

Required Evidence:
    An unsatisfiable core containing conflicting assignments or state checks on resource variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    get_variable_names_all,
)


class ResourceStateContradictionRule(LogicRule):
    """Logic rule for detecting resource state contradictions.

    This rule checks the unsatisfiable core for conflicting boolean assignments on variables
    associated with resources (e.g., a file being simultaneously open and closed).

    Bug Class Detected:
        Logical contradiction (resource state contradiction).

    Required Evidence:
        ContradictionContext with conflicting boolean state assignments on resource-related variables.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "Resource State Contradiction"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a resource state contradiction.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a resource state contradiction is detected, False otherwise.
        """
        names = get_variable_names_all(ctx.core)
        resource_names = [
            n
            for n in names
            if any(
                tag in n.lower()
                for tag in ("resource", "file", "socket", "handle", "stream", "lock")
            )
        ]
        if not resource_names:
            return False

        bool_values = extract_bool_assignments(ctx.core)
        for name in resource_names:
            values = bool_values.get(name)
            if values and len(values) > 1:
                return True

        return False
