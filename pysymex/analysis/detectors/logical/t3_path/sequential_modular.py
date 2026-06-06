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

"""Sequential Modular Contradiction logic rule.

This module implements the sequential modular contradiction rule (Tier 3), which
identifies contradictions when a single symbolic variable is constrained by multiple
modulo operations under the same modulus but requiring different remainders.

Bug Class Detected:
    Logical contradiction resulting in infeasible code paths.

Required Evidence:
    An unsatisfiable core containing modulo equality constraints on the same variable,
    with matching moduli but conflicting remainder values.

Issue Kinds:
    IssueKind.LOGICAL_CONTRADICTION
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import core_has_operator, extract_modulo_equalities
import z3


class SequentialModularRule(LogicRule):
    """Logic rule for detecting sequential modular contradictions.

    Checks the unsatisfiable core for a single symbolic variable subjected to conflicting
    modulo operations under the same modulus (e.g., `x % 3 == 1` and `x % 3 == 2`).

    Bug Class Detected:
        Logical contradiction (impossible path branch).

    Required Evidence:
        ContradictionContext with modulo equalities extracted from the unsat core showing
        mismatched remainders for a shared variable and modulus.

    Issue Kinds:
        IssueKind.LOGICAL_CONTRADICTION
    """

    name = "Sequential Modular Contradiction"
    tier = 3

    def matches(self, ctx: ContradictionContext) -> bool:
        """Determine if the contradiction context contains a sequential modular contradiction.

        Checks if any variable in the unsatisfiable core is constrained to have different remainders
        modulo the same modulus.

        Args:
            ctx (ContradictionContext): The contradiction context containing the unsat core.

        Returns:
            bool: True if a modular contradiction is found, False otherwise.
        """
        if not core_has_operator(ctx.core, {z3.Z3_OP_MUL}):
            return False

        seen: dict[tuple[str, int], int] = {}
        for var, modulus, remainder in extract_modulo_equalities(ctx.core):
            normalized_modulus = abs(modulus)
            if normalized_modulus == 0:
                continue
            key = (var, normalized_modulus)
            normalized_remainder = remainder % normalized_modulus
            previous = seen.get(key)
            if previous is not None and previous != normalized_remainder:
                return True
            seen[key] = normalized_remainder
        return False
