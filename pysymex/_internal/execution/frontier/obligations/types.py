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

"""Record types for frontier obligation capsules."""

from __future__ import annotations

from dataclasses import dataclass

CapsuleDigest = tuple[object, ...]


@dataclass(frozen=True, slots=True)
class LiveSemanticFootprint:
    """Conservative live-root summary for a shadow POLAR capsule."""

    pc: int
    state_structural_hash: int
    stack_depth: int
    local_names: tuple[str, ...]
    global_names: tuple[str, ...]
    memory_cell_count: int
    active_exception: bool
    pending_reraise_exception: bool
    write_event_count: int
    detector_obligation_count: int
    detector_obligation_keys: tuple[object, ...]
    unsupported_live_count: int = 0
    havoc_live_count: int = 0


@dataclass(frozen=True, slots=True)
class ObligationCapsule:
    """Shadow POLAR work item derived from an existing ``VMState``.

    The capsule is not executable. In runtime CEGIS mode it may identify exact
    certificate-covered pruning candidates, but live removal remains owned by
    checkpoint-backed CEGIS evidence-application gates.
    """

    capsule_id: str
    parent_id: str | None
    path_id: int
    depth: int
    footprint: LiveSemanticFootprint
    constraint_atom_ids: tuple[int, ...]
    pending_constraint_count: int
    branch_trace_length: int
    estimated_resident_units: int

    @property
    def constraint_atom_count(self) -> int:
        """Return the number of constraint atoms captured by this capsule."""
        return len(self.constraint_atom_ids)


@dataclass(frozen=True, slots=True)
class FrontierTelemetry:
    """Aggregate shadow-frontier metrics for migration baselines."""

    capsule_count: int
    constraint_atom_count: int
    pending_constraint_count: int
    estimated_resident_units: int
    detector_obligation_count: int
    unsupported_live_count: int
    havoc_live_count: int
