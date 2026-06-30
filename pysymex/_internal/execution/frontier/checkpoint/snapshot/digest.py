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

"""Frontier snapshot digest and resident-unit sizing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.evidence import detector_obligation_digest

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.checkpoint.snapshot.record import (
        FrontierStateSnapshot,
    )
    from pysymex._internal.execution.frontier.obligations.types import CapsuleDigest


def snapshot_digest(
    snapshot: FrontierStateSnapshot,
    *,
    estimated_resident_units: int | None = None,
) -> CapsuleDigest:
    """Return the phase-0 capsule digest represented by this snapshot."""
    resident_units = (
        estimated_resident_units
        if estimated_resident_units is not None
        else snapshot_estimated_resident_units(snapshot)
    )
    return (
        snapshot.path_id,
        snapshot.depth,
        snapshot.pc,
        snapshot.state_structural_hash,
        len(snapshot.stack),
        tuple(name for name, _ in snapshot.local_vars),
        tuple(name for name, _ in snapshot.global_vars),
        len(snapshot.memory),
        snapshot.active_exception is not None,
        snapshot.pending_reraise_exception is not None,
        len(snapshot.write_events),
        len(snapshot.deferred_detector_issues),
        detector_obligation_digest(snapshot.deferred_detector_issues),
        0,
        snapshot.havoc_live_count,
        snapshot.constraint_atom_ids,
        snapshot.pending_constraint_count,
        len(snapshot.branch_trace),
        resident_units,
    )


def snapshot_estimated_resident_units(snapshot: FrontierStateSnapshot) -> int:
    """Return the same deterministic size proxy used by shadow capsules."""
    return (
        len(snapshot.stack)
        + len(snapshot.local_vars)
        + len(snapshot.global_vars)
        + len(snapshot.memory)
        + len(snapshot.path_constraints)
        + len(snapshot.branch_trace)
        + len(snapshot.deferred_detector_issues)
        + len(snapshot.write_events)
    )
