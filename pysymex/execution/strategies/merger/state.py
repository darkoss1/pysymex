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

"""Concrete symbolic state merger composition."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.strategies.merger.equality import StateMergerEqualityMixin
from pysymex.execution.strategies.merger.join import StateMergerJoinMixin
from pysymex.execution.strategies.merger.lifecycle import StateMergerLifecycleMixin
from pysymex.execution.strategies.merger.pending import StateMergerPendingMixin
from pysymex.execution.strategies.merger.symbolic import StateMergerSymbolicMixin
from pysymex.execution.strategies.merger.types import MergePolicy, MergeStatistics

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class StateMerger(
    StateMergerJoinMixin,
    StateMergerPendingMixin,
    StateMergerEqualityMixin,
    StateMergerSymbolicMixin,
    StateMergerLifecycleMixin,
):
    """Merges equivalent states at control-flow join points using symbolic merging.

    Composes join detection, pending queues, structural equality checks, and
    symbolic widening of locals/globals when policy thresholds are met.

    Limitations:
        Merging can hide feasible differences between paths when similarity
        thresholds are too aggressive; conservative policy disables symbolic
        merges and relies on exact structural matches only.
    """

    def __init__(
        self,
        policy: MergePolicy = MergePolicy.MODERATE,
        max_constraints_for_merge: int = 50,
        similarity_threshold: float = 0.7,
        max_symbolic_merge_candidates: int = 32,
        disable_after_unproductive_attempts: int = 128,
    ) -> None:
        """Initialize merge policy, thresholds, and per-execution statistics."""
        self.policy = policy
        self.max_constraints_for_merge = max_constraints_for_merge
        self.similarity_threshold = similarity_threshold
        self.max_symbolic_merge_candidates = max(1, max_symbolic_merge_candidates)
        self.disable_after_unproductive_attempts = max(1, disable_after_unproductive_attempts)
        self._disabled_for_execution = False
        self.stats = MergeStatistics()
        self.join_points: set[int] = set()
        self.pending_states: dict[int, dict[int, list[VMState]]] = {}
