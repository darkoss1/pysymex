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

"""Modular contradiction logical contradiction rule.

Detects contradictions where a single variable is restricted to conflicting remainders
under the same modulus (e.g. x % 2 == 0 and x % 2 == 1).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    core_has_operator,
    extract_modulo_equalities,
)


class ModularContradictionRule(LogicRule):
    """Rule that matches contradictions involving a single variable and conflicting modulo remainders."""

    name = "Modular Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a modular contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains only 1 variable, lacks multiplication and addition,
            and contains conflicting remainders for the same variable and modulus, otherwise False.
        """
        if count_variables(ctx.core) != 1:
            return False
        if core_has_operator(ctx.core, {z3.Z3_OP_MUL, z3.Z3_OP_ADD}):
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
