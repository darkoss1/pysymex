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

"""Bounded runtime CEGIS telemetry snapshots."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CegisRuntimeStats:
    """Snapshot of CEGIS preview/application telemetry."""

    enabled: bool
    bid_count: int
    evidence_preview_count: int
    evidence_preview_removable_state_count: int
    evidence_preview_invalid_count: int
    evidence_apply_count: int
    evidence_apply_removed_state_count: int
    evidence_apply_invalid_count: int
    runtime_execution_select_count: int
    runtime_execution_no_selection_count: int

    def as_dict(self) -> dict[str, object]:
        """Return a bounded diagnostics dictionary for execution results."""
        return {
            "enabled": self.enabled,
            "bid_count": self.bid_count,
            "evidence_preview_count": self.evidence_preview_count,
            "evidence_preview_removable_state_count": (self.evidence_preview_removable_state_count),
            "evidence_preview_invalid_count": self.evidence_preview_invalid_count,
            "evidence_apply_count": self.evidence_apply_count,
            "evidence_apply_removed_state_count": self.evidence_apply_removed_state_count,
            "evidence_apply_invalid_count": self.evidence_apply_invalid_count,
            "runtime_execution_select_count": self.runtime_execution_select_count,
            "runtime_execution_no_selection_count": self.runtime_execution_no_selection_count,
        }
