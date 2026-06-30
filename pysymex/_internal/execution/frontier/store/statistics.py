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

"""Aggregate statistics for live frontier work storage."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.obligations.telemetry import collect_frontier_telemetry
from pysymex._internal.execution.frontier.store.stats import FrontierWorkStoreStats

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.entries import FrontierQueueEntry
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule

    class WorkStoreStatsContract:
        """Static surface required by frontier stats mixins."""

        _runtime_mode: FrontierRuntimeMode
        _entries: dict[int, FrontierQueueEntry]
        _capsules: dict[int, ObligationCapsule]
        _checkpoints: dict[int, FrontierCheckpoint]
        _compacted_entry_count: int
        _capsule_digest_mismatch_count: int
        _reconstruction_mismatch_count: int
        _compaction_denied_count: int
        _spill_denied_count: int

else:

    class WorkStoreStatsContract:
        """Runtime placeholder for the type-checking-only stats mixin surface."""


class WorkStoreStatsMixin(WorkStoreStatsContract):
    """Collect aggregate live frontier telemetry for result diagnostics."""

    def collect_stats(self) -> FrontierWorkStoreStats:
        """Return aggregate live frontier telemetry for result diagnostics."""
        telemetry = collect_frontier_telemetry(self._capsules.values())
        return FrontierWorkStoreStats(
            enabled=self._runtime_mode.shadow_telemetry_enabled,
            compact_queueing_enabled=self._runtime_mode.compact_queueing_enabled,
            checkpoint_count=len(self._checkpoints),
            compacted_entry_count=self._compacted_entry_count,
            spilled_entry_count=sum(entry.is_spilled for entry in self._entries.values()),
            capsule_digest_mismatch_count=self._capsule_digest_mismatch_count,
            reconstruction_mismatch_count=self._reconstruction_mismatch_count,
            compaction_denied_count=self._compaction_denied_count,
            spill_denied_count=self._spill_denied_count,
            telemetry=telemetry,
        )
