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

"""Compaction and spill requests for live frontier work storage.

The live store owns payload mappings. This module owns the policy transition
that replaces one resident entry with an exact checkpoint or spilled payload
while preserving explicit denial counters.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.compaction import (
    FrontierCompactionDecision,
    FrontierCompactionStatus,
)
from pysymex._internal.execution.frontier.entries import FrontierQueueEntry
from pysymex._internal.execution.frontier.spill.policy import (
    FrontierSpillDecision,
    FrontierSpillPolicy,
)

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode

    class WorkStoreRequestContract:
        """Static surface required by frontier request mixins."""

        _runtime_mode: FrontierRuntimeMode
        _entries: dict[int, FrontierQueueEntry]
        _checkpoints: dict[int, FrontierCheckpoint]
        _compacted_entry_count: int
        _compaction_denied_count: int
        _spill_denied_count: int

        def ensure_checkpoint(self, state_id: int) -> FrontierCheckpoint | None:
            """Return an exact checkpoint for a live state when available."""
            ...

else:

    class WorkStoreRequestContract:
        """Runtime placeholder for the type-checking-only request mixin surface."""


class WorkStoreRequestMixin(WorkStoreRequestContract):
    """Apply compaction and spill requests to live frontier entries."""

    def request_compaction(self, state_id: int) -> FrontierCompactionDecision:
        """Replace one resident entry with an exact in-memory checkpoint when possible."""
        entry = self._entries.get(state_id)
        if entry is None:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.NOT_LIVE,
                explanation="frontier entry is not live",
            )
            self._compaction_denied_count += 1
            return decision
        if entry.is_compact:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.ALREADY_COMPACT,
                explanation="frontier entry is already compact",
            )
            self._compaction_denied_count += 1
            return decision

        checkpoint = self.ensure_checkpoint(state_id)
        if checkpoint is None:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.CHECKPOINT_UNAVAILABLE,
                explanation="exact checkpoint is not available",
            )
            self._compaction_denied_count += 1
            return decision

        compacted_entry = FrontierQueueEntry(checkpoint=checkpoint)
        self._entries[state_id] = compacted_entry
        self._compacted_entry_count += 1
        return FrontierCompactionDecision(
            status=FrontierCompactionStatus.COMPACTED,
            explanation="frontier entry compacted to an exact checkpoint",
            compacted_entry=compacted_entry,
        )

    def request_spill(
        self,
        state_id: int,
        policy: FrontierSpillPolicy | None = None,
    ) -> FrontierSpillDecision:
        """Evaluate and apply a safe spill request for one live entry."""
        entry = self._entries.get(state_id)
        active_policy = policy if policy is not None else FrontierSpillPolicy()
        if entry is None:
            decision = active_policy.evaluate_missing()
        else:
            spill_entry = entry
            if (
                active_policy.filesystem_spill_enabled
                and self._runtime_mode.certificate_pruning_enabled
                and not entry.is_compact
            ):
                checkpoint = self.ensure_checkpoint(state_id)
                if checkpoint is not None:
                    spill_entry = FrontierQueueEntry(checkpoint=checkpoint)
            decision = active_policy.evaluate(spill_entry, state_id=state_id)
        if decision.can_spill and decision.spilled_entry is not None:
            self._entries[state_id] = decision.spilled_entry
            self._checkpoints.pop(state_id, None)
        else:
            self._spill_denied_count += 1
        return decision
