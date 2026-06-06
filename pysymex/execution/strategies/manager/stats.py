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

"""Worklist statistics assembly for POLAR path managers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.execution.frontier import FrontierRuntimeMode, FrontierWorkStore
    from pysymex.execution.scheduling.cegis import CegisRuntimeController


def polar_manager_stats(
    *,
    frontier: FrontierWorkStore,
    cegis_runtime: CegisRuntimeController,
    frontier_runtime_mode: FrontierRuntimeMode,
    path_policy: str,
    path_decisions: dict[str, str],
    covered_pc_count: int,
    total_rewards: float,
    estimated_resident_units_total: int,
    pressure_compaction_count: int,
    pressure_compaction_trigger_count: int,
) -> dict[str, object]:
    """Return bounded worklist diagnostics for a POLAR path manager."""
    frontier_stats = frontier.collect_stats()
    shadow_telemetry = frontier_stats.telemetry
    cegis_stats = cegis_runtime.collect_stats(
        frontier,
        enabled=frontier_runtime_mode.shadow_telemetry_enabled,
    )
    return {
        "arms": {},
        "path_arms": {},
        "path_policy": path_policy,
        "path_decisions": dict(path_decisions),
        "topological_arms": {},
        "covered_pcs": covered_pc_count,
        "total_rewards": total_rewards,
        "frontier_mode": frontier_runtime_mode.value,
        "shadow_frontier": {
            "enabled": frontier_stats.enabled,
            "capsule_count": shadow_telemetry.capsule_count,
            "checkpoint_count": frontier_stats.checkpoint_count,
            "compacted_entry_count": frontier_stats.compacted_entry_count,
            "spilled_entry_count": frontier_stats.spilled_entry_count,
            "compact_queueing_enabled": frontier_stats.compact_queueing_enabled,
            "capsule_digest_mismatch_count": frontier_stats.capsule_digest_mismatch_count,
            "reconstruction_mismatch_count": frontier_stats.reconstruction_mismatch_count,
            "compaction_denied_count": frontier_stats.compaction_denied_count,
            "spill_denied_count": frontier_stats.spill_denied_count,
            "constraint_atom_count": shadow_telemetry.constraint_atom_count,
            "pending_constraint_count": shadow_telemetry.pending_constraint_count,
            "estimated_resident_units": shadow_telemetry.estimated_resident_units,
            "runtime_estimated_resident_units": estimated_resident_units_total,
            "pressure_compaction_count": pressure_compaction_count,
            "pressure_compaction_trigger_count": pressure_compaction_trigger_count,
            "detector_obligation_count": shadow_telemetry.detector_obligation_count,
            "unsupported_live_count": shadow_telemetry.unsupported_live_count,
            "havoc_live_count": shadow_telemetry.havoc_live_count,
        },
        "shadow_cegis": cegis_stats.as_dict(),
    }


__all__ = ["polar_manager_stats"]
