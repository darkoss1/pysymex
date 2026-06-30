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

"""Exact state-coverage predicates shared by merging and loop convergence.

This module owns structural coverage checks only. It does not query the solver,
apply widening, schedule states, or classify detector evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.merger.equality.mixin import StateMergerEqualityMixin

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


class _ExactStateEquality(StateMergerEqualityMixin):
    """Stateless composition of the state-merger equality predicates."""

    def payload_equal(
        self,
        left: VMState,
        right: VMState,
        *,
        ignore_visited_pcs: bool = False,
        ignore_local_vars: bool = False,
    ) -> bool:
        """Expose exact payload equality to package-level coverage predicates."""
        return self._state_payload_equal(
            left,
            right,
            ignore_visited_pcs=ignore_visited_pcs,
            ignore_local_vars=ignore_local_vars,
        )


_EQUALITY = _ExactStateEquality()


def constraints_exactly_subsume(subsumer: VMState, subsumed: VMState) -> bool:
    """Return whether ``subsumer`` has an exact constraint prefix of ``subsumed``."""
    subsumer_constraints = subsumer.path_constraints.to_list()
    subsumed_constraints = subsumed.path_constraints.to_list()
    if len(subsumer_constraints) > len(subsumed_constraints):
        return False
    return all(
        _EQUALITY.constraints_equal(left, right)
        for left, right in zip(subsumer_constraints, subsumed_constraints, strict=False)
    )


def state_exactly_covers(subsumer: VMState, subsumed: VMState) -> bool:
    """Return whether a prior loop-header state exactly covers a recurrent state.

    Coverage ignores accumulated PC-coverage telemetry and loop counters because they
    do not affect execution semantics. All state payload and constraint-prefix checks
    remain structural and exact; hash equality alone is never accepted as evidence.
    """
    return (
        subsumer.pc == subsumed.pc
        and _EQUALITY.payload_equal(
            subsumer,
            subsumed,
            ignore_visited_pcs=True,
        )
        and constraints_exactly_subsume(subsumer, subsumed)
    )


def state_payload_equal_except_locals(left: VMState, right: VMState) -> bool:
    """Return whether loop states differ only in local-variable payload or constraints."""
    return left.pc == right.pc and _EQUALITY.payload_equal(
        left,
        right,
        ignore_visited_pcs=True,
        ignore_local_vars=True,
    )
