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

"""Parity contradiction logical contradiction rule.

Detects contradictions where a single variable has conflicting parity assertions (even and odd).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
import z3
from pysymex.analysis.detectors.logical.utils import (
    count_variables,
    core_has_operator,
    extract_modulo_equalities,
)


class ParityContradictionRule(LogicRule):
    """Rule that matches contradictions involving a single variable and conflicting parity remainders."""

    name = "Parity Contradiction"
    tier = 1

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a parity contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core contains only 1 variable, has modulo/remainder operators,
            and contains conflicting even/odd remainders for that variable, otherwise False.
        """
        if count_variables(ctx.core) != 1:
            return False
        if not core_has_operator(ctx.core, {z3.Z3_OP_MOD, z3.Z3_OP_REM}):
            return False

        seen: dict[str, int] = {}
        for var, modulus, remainder in extract_modulo_equalities(ctx.core):
            if abs(modulus) != 2:
                continue
            normalized = remainder % 2
            previous = seen.get(var)
            if previous is not None and previous != normalized:
                return True
            seen[var] = normalized
        return False
