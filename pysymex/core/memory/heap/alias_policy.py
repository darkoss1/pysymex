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

"""Heap alias-query policy for symbolic addresses.

This module owns the heap-level interpretation of address equality queries.
It converts solver SAT/UNSAT/UNKNOWN results into alias evidence without
letting inconclusive answers become proof.
"""

from __future__ import annotations

import z3

from pysymex.core.memory.alias_queries import AliasQueryResult
from pysymex.core.memory.types import SymbolicAddress
from pysymex.core.solver.engine.queries import check_sat_result


class SymbolicHeapAliasPolicyMixin:
    """Own conservative may/must alias policy for heap address pairs."""

    def _may_alias(self, condition: z3.BoolRef) -> bool:
        """Return whether an alias condition is not proved infeasible."""
        result = check_sat_result([condition])
        return not result.is_unsat

    @staticmethod
    def _same_region_result(
        addr1: SymbolicAddress,
        addr2: SymbolicAddress,
    ) -> AliasQueryResult | None:
        """Return refuted evidence for model-level disjoint memory regions."""
        if addr1.same_region(addr2):
            return None
        return AliasQueryResult.refuted("different_regions")

    @staticmethod
    def _may_condition_result(condition: z3.BoolRef) -> AliasQueryResult:
        """Return structured evidence for satisfiability of an alias condition."""
        result = check_sat_result([condition])
        if result.is_sat:
            return AliasQueryResult.established()
        if result.is_unsat:
            return AliasQueryResult.refuted()
        return AliasQueryResult.unknown("solver_unknown")

    def may_alias(self, addr1: SymbolicAddress, addr2: SymbolicAddress) -> bool:
        """Return whether equal effective addresses remain possible.

        Addresses in different regions are treated as distinct by this model.
        Solver ``UNKNOWN`` conservatively returns ``True``.
        """
        result = self.may_alias_result(addr1, addr2)
        return result.is_established or result.is_unknown

    def may_alias_result(
        self,
        addr1: SymbolicAddress,
        addr2: SymbolicAddress,
    ) -> AliasQueryResult:
        """Return structured evidence for whether equal addresses remain possible."""
        region_result = self._same_region_result(addr1, addr2)
        if region_result is not None:
            return region_result
        return self._may_condition_result(addr1.effective_address == addr2.effective_address)

    def must_alias(self, addr1: SymbolicAddress, addr2: SymbolicAddress) -> bool:
        """Return whether unequal effective addresses are proved infeasible.

        Solver ``UNKNOWN`` returns ``False`` rather than claiming equality.
        """
        return self.must_alias_result(addr1, addr2).is_established

    def must_alias_result(
        self,
        addr1: SymbolicAddress,
        addr2: SymbolicAddress,
    ) -> AliasQueryResult:
        """Return structured evidence for whether two addresses must be equal."""
        region_result = self._same_region_result(addr1, addr2)
        if region_result is not None:
            return region_result
        result = check_sat_result([addr1.effective_address != addr2.effective_address])
        if result.is_unsat:
            return AliasQueryResult.established()
        if result.is_sat:
            return AliasQueryResult.refuted()
        return AliasQueryResult.unknown("solver_unknown")


__all__ = ["SymbolicHeapAliasPolicyMixin"]
