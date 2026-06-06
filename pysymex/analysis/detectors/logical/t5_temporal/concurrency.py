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

"""Concurrency Contradiction logic rule.

This module implements the concurrency contradiction logic rule (Tier 5), which detects
contradictions in constraints involving lock acquisition, thread states, atomic execution,
or race condition signals.

Bug Class Detected:
    Logical contradiction (concurrency contradiction).

Required Evidence:
    An unsatisfiable core containing contradictory boolean assignments or inconsistent comparisons
    on lock- or thread-related variables.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bool_assignments,
    extract_var_var_comparisons,
    get_variable_names_all,
)


class ConcurrencyContradictionRule(LogicRule):
    """Logic rule for detecting concurrency contradictions.

    This rule checks the unsatisfiable core for conflicting assignments or relational
    inconsistencies on variables representing locks, mutexes, threads, or atomic regions.

    Bug Class Detected:
        Logical contradiction (concurrency contradiction).

    Required Evidence:
        ContradictionContext with contradictory constraints on lock/thread variables.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "Concurrency Contradiction"
    tier = 5

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a concurrency contradiction.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a concurrency contradiction is detected, False otherwise.
        """
        names = get_variable_names_all(ctx.core)
        lower_names = {n.lower() for n in names}
        has_concurrency_signal = any(
            tag in n for n in lower_names for tag in ("lock", "mutex", "thread", "race", "atomic")
        )
        if not has_concurrency_signal:
            return False

        bool_values = extract_bool_assignments(ctx.core)
        for name, values in bool_values.items():
            lname = name.lower()
            if any(tag in lname for tag in ("lock", "mutex", "thread")) and len(values) > 1:
                return True

        relations = extract_var_var_comparisons(ctx.core)
        rel = {(a, op, b) for a, op, b in relations}

        for a, op, b in relations:
            la = a.lower()
            lb = b.lower()
            if not any(tag in la for tag in ("lock", "mutex", "thread")):
                continue
            if not any(tag in lb for tag in ("lock", "mutex", "thread")):
                continue
            if op == "<" and ((b, "<", a) in rel or (b, "<=", a) in rel):
                return True
            if op == "<=" and (b, "<", a) in rel:
                return True
            if op == ">" and ((b, ">", a) in rel or (b, ">=", a) in rel):
                return True
            if op == ">=" and (b, ">", a) in rel:
                return True

        return False
