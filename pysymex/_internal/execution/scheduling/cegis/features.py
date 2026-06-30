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

"""Feature extraction for phase-0 CEGIS shadow scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule


@dataclass(frozen=True, slots=True)
class SchedulingFeatureVector:
    """Context made visible to CEGIS before any learned policy exists."""

    capsule_id: str
    pc: int
    depth: int
    constraint_atom_count: int
    pending_constraint_count: int
    detector_obligation_count: int
    estimated_resident_units: int
    estimated_reconstruct_units: int
    unsupported_live_count: int
    havoc_live_count: int
    memory_pressure: float


def feature_vector_from_capsule(
    capsule: ObligationCapsule,
    *,
    memory_pressure: float = 0.0,
) -> SchedulingFeatureVector:
    """Build a phase-0 CEGIS feature vector from a POLAR shadow capsule."""
    return SchedulingFeatureVector(
        capsule_id=capsule.capsule_id,
        pc=capsule.footprint.pc,
        depth=capsule.depth,
        constraint_atom_count=capsule.constraint_atom_count,
        pending_constraint_count=capsule.pending_constraint_count,
        detector_obligation_count=capsule.footprint.detector_obligation_count,
        estimated_resident_units=capsule.estimated_resident_units,
        estimated_reconstruct_units=max(1, capsule.estimated_resident_units),
        unsupported_live_count=capsule.footprint.unsupported_live_count,
        havoc_live_count=capsule.footprint.havoc_live_count,
        memory_pressure=memory_pressure,
    )
