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

"""Runtime CEGIS telemetry accounting.

This module owns the deterministic counters emitted in runtime CEGIS stats.
It does not inspect frontier state, select proof actions, or decide whether an
evidence outcome is valid to apply.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.cegis.runtime.stats import CegisRuntimeStats

if TYPE_CHECKING:
    from pysymex._internal.execution.scheduling.cegis.application import EvidenceApplicationPlan


@dataclass(slots=True)
class CegisRuntimeAccounting:
    """Mutable telemetry counters for runtime CEGIS dispatch."""

    evidence_preview_count: int = 0
    evidence_preview_removable_state_count: int = 0
    evidence_preview_invalid_count: int = 0
    evidence_apply_count: int = 0
    evidence_apply_removed_state_count: int = 0
    evidence_apply_invalid_count: int = 0
    runtime_execution_select_count: int = 0
    runtime_execution_no_selection_count: int = 0

    def record_evidence_preview(self, plan: EvidenceApplicationPlan) -> None:
        """Record a non-mutating CEGIS evidence preview."""
        self.evidence_preview_count += 1
        if plan.invalid_removal_attempt:
            self.evidence_preview_invalid_count += 1
        if plan.can_remove:
            self.evidence_preview_removable_state_count += len(plan.removable_state_ids)

    def record_evidence_apply(
        self,
        plan: EvidenceApplicationPlan,
        *,
        removed_state_count: int,
    ) -> None:
        """Record a CEGIS evidence application attempt."""
        self.evidence_apply_count += 1
        if plan.invalid_removal_attempt:
            self.evidence_apply_invalid_count += 1
        self.evidence_apply_removed_state_count += removed_state_count

    def record_runtime_execution_selection(self, selected: bool) -> None:
        """Record whether detector-first runtime selection found live work."""
        if selected:
            self.runtime_execution_select_count += 1
        else:
            self.runtime_execution_no_selection_count += 1

    def collect_stats(self, *, enabled: bool, bid_count: int) -> CegisRuntimeStats:
        """Return a bounded immutable runtime CEGIS telemetry snapshot."""
        return CegisRuntimeStats(
            enabled=enabled,
            bid_count=bid_count,
            evidence_preview_count=self.evidence_preview_count,
            evidence_preview_removable_state_count=(self.evidence_preview_removable_state_count),
            evidence_preview_invalid_count=self.evidence_preview_invalid_count,
            evidence_apply_count=self.evidence_apply_count,
            evidence_apply_removed_state_count=self.evidence_apply_removed_state_count,
            evidence_apply_invalid_count=self.evidence_apply_invalid_count,
            runtime_execution_select_count=self.runtime_execution_select_count,
            runtime_execution_no_selection_count=self.runtime_execution_no_selection_count,
        )
