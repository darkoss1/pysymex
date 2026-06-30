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

"""Cheap live-state features for POLAR runtime scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


@dataclass(frozen=True, slots=True)
class FrontierRuntimeFeatures:
    """Cheap live-state facts used for default runtime scheduling.

    These features are not proof artifacts. They may rank resident work for
    execution, but CEGIS removal still requires full capsules/checkpoints.
    """

    capsule_id: str
    detector_obligation_count: int
    pending_constraint_count: int
    estimated_resident_units: int
    unsupported_live_count: int = 0
    havoc_live_count: int = 0


def build_frontier_runtime_features(state_id: int, state: VMState) -> FrontierRuntimeFeatures:
    """Build low-cost scheduling features without capsule digests."""
    return FrontierRuntimeFeatures(
        capsule_id=f"path:{state_id}",
        detector_obligation_count=len(state.deferred_detector_issues),
        pending_constraint_count=state.pending_constraint_count,
        estimated_resident_units=estimate_state_resident_units(state),
    )


def estimate_state_resident_units(state: VMState) -> int:
    """Return a cheap relative size estimate for one resident VMState."""
    return max(
        1,
        len(state.stack)
        + len(state.local_vars)
        + len(state.global_vars)
        + len(state.memory)
        + len(state.path_constraints)
        + len(state.branch_trace)
        + len(state.deferred_detector_issues)
        + len(state.write_events),
    )
