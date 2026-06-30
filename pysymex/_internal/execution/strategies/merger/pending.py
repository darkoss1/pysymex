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

"""Pending-state buckets keyed by join PC and structural hash.

Queues incoming ``VMState`` objects until a compatible partner arrives or merge
policy disables further attempts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.merger.equality.coverage import (
    constraints_exactly_subsume,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract


class StateMergerPendingMixin(StateMergerMixinContract):
    """Queue states at join points and attempt merges when partners arrive."""

    def add_state_for_merge(self, state: VMState) -> VMState | None:
        """Add a state for potential merging. Returns merged state or None."""
        pc = state.pc
        if pc not in self.pending_states:
            self.pending_states[pc] = {}

        target_hash = self._structural_hash(state)
        if target_hash not in self.pending_states[pc]:
            self.pending_states[pc][target_hash] = []

        pending = self.pending_states[pc][target_hash]
        self.stats.states_before_merge += 1

        if (
            self.stats.states_before_merge > self.disable_after_unproductive_attempts
            and self.stats.merge_operations == 0
            and self.stats.subsumption_hits == 0
        ):
            self._disabled_for_execution = True
            pending.append(state)
            self.stats.states_after_merge += 1
            return state

        i = 0
        subsumption_start = max(0, len(pending) - self.max_symbolic_merge_candidates)
        while i < len(pending):
            if i < subsumption_start:
                i += 1
                continue
            existing = pending[i]

            if self._state_payload_equal(existing, state):
                if self._constraints_subsume(existing, state):
                    self.stats.subsumption_hits += 1
                    return None
                if self._constraints_subsume(state, existing):
                    pending.pop(i)
                    self.stats.states_after_merge = max(0, self.stats.states_after_merge - 1)
                    self.stats.subsumption_hits += 1
                    continue
            i += 1

        symbolic_start = max(0, len(pending) - self.max_symbolic_merge_candidates)
        for offset, existing in enumerate(pending[symbolic_start:]):
            if self._can_merge_symbolically(state, existing):
                merged = self._merge_states_symbolically(state, existing)
                if merged:
                    pending.pop(symbolic_start + offset)
                    pending.append(merged)
                    self.stats.merge_operations += 1
                    return merged
        pending.append(state)
        self.stats.states_after_merge += 1
        return state

    def _constraints_subsume(self, subsumer: VMState, subsumed: VMState) -> bool:
        """Return True when ``subsumer`` safely covers ``subsumed`` exactly.
        Assumes payload equality has already been verified.
        """
        return constraints_exactly_subsume(subsumer, subsumed)
