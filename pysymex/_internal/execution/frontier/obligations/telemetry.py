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

"""Aggregate telemetry for frontier obligation capsules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.obligations.types import (
    FrontierTelemetry,
    ObligationCapsule,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


def collect_frontier_telemetry(capsules: Iterable[ObligationCapsule]) -> FrontierTelemetry:
    """Aggregate phase-0 telemetry over shadow POLAR capsules."""
    capsule_count = 0
    constraint_atom_count = 0
    pending_constraint_count = 0
    estimated_resident_units = 0
    detector_obligation_count = 0
    unsupported_live_count = 0
    havoc_live_count = 0

    for capsule in capsules:
        capsule_count += 1
        constraint_atom_count += capsule.constraint_atom_count
        pending_constraint_count += capsule.pending_constraint_count
        estimated_resident_units += capsule.estimated_resident_units
        detector_obligation_count += capsule.footprint.detector_obligation_count
        unsupported_live_count += capsule.footprint.unsupported_live_count
        havoc_live_count += capsule.footprint.havoc_live_count

    return FrontierTelemetry(
        capsule_count=capsule_count,
        constraint_atom_count=constraint_atom_count,
        pending_constraint_count=pending_constraint_count,
        estimated_resident_units=estimated_resident_units,
        detector_obligation_count=detector_obligation_count,
        unsupported_live_count=unsupported_live_count,
        havoc_live_count=havoc_live_count,
    )
