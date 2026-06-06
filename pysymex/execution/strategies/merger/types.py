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

"""Merge policy enums, statistics, and mixin protocol for join-point merging.

State merging is an optimization: merged states must remain sound over-approximations
of the individual paths being joined. Policies control how aggressively PySyMex
attempts symbolic merges versus structural equality checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING


class MergePolicy(Enum):
    """Merge aggressiveness policies for state merging."""

    CONSERVATIVE = auto()
    MODERATE = auto()
    AGGRESSIVE = auto()


@dataclass
class MergeStatistics:
    """Accumulator for state-merging statistics."""

    states_before_merge: int = 0
    states_after_merge: int = 0
    merge_operations: int = 0
    subsumption_hits: int = 0

    @property
    def reduction_ratio(self) -> float:
        """Return ``1 - states_after / states_before`` for merge effectiveness."""
        if self.states_before_merge == 0:
            return 0.0
        return 1.0 - (self.states_after_merge / self.states_before_merge)


@dataclass
class AbstractVarInfo:
    """Abstract information about a variable at a merge point."""

    interval_lo: int | None = None
    interval_hi: int | None = None
    may_be_none: bool = False
    must_be_type: str | None = None


if TYPE_CHECKING:
    import dis
    import types

    import z3

    from pysymex.core.state.record import VMState

    class StateMergerMixinContract:
        """Structural protocol listing attributes mixed into ``StateMerger``."""

        disable_after_unproductive_attempts: int
        join_points: set[int]
        max_constraints_for_merge: int
        max_symbolic_merge_candidates: int
        pending_states: dict[int, dict[int, list[VMState]]]
        policy: MergePolicy
        similarity_threshold: float
        stats: MergeStatistics
        _disabled_for_execution: bool

        def _can_merge_symbolically(self, state1: VMState, state2: VMState) -> bool: ...

        def _merge_states_symbolically(
            self, state1: VMState, state2: VMState
        ) -> VMState | None: ...

        def _state_payload_equal(self, state1: VMState, state2: VMState) -> bool: ...

        def _structural_hash(self, state: VMState) -> int: ...

        def constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool: ...

        def detect_join_points(
            self, instructions: list[dis.Instruction], code: types.CodeType | None = None
        ) -> set[int]: ...

        def values_structurally_equal(self, left: object, right: object) -> bool: ...

else:

    class StateMergerMixinContract:
        pass
