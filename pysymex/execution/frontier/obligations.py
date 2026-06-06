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

"""Phase-0 POLAR obligation capsules.

The owner of these records is ``execution.frontier``. They are conservative
snapshots of current ``VMState`` facts used for POLAR telemetry, exact
checkpoint-duplicate pruning, and reconstruction validation. Compact POLAR
queueing is gated through checkpoints, not capsules alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex.execution.frontier.evidence import detector_obligation_digest, havoc_root_count

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex.core.state.record import VMState

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


def build_shadow_capsule(
    state: "VMState",
    *,
    capsule_id: str | None = None,
    parent_id: str | None = None,
) -> ObligationCapsule:
    """Build a conservative POLAR shadow capsule from ``state``.

    The function reads VMState metadata only. It does not run the solver,
    change execution-visible state, or classify path feasibility.
    """
    constraint_atom_ids = state.path_constraints.sorted_constraint_hashes()
    branch_trace_length = len(state.branch_trace)
    footprint = LiveSemanticFootprint(
        pc=state.pc,
        state_structural_hash=state_structural_hash(state),
        stack_depth=len(state.stack),
        local_names=state.local_vars.sorted_keys(),
        global_names=state.global_vars.sorted_keys(),
        memory_cell_count=len(state.memory),
        active_exception=state.active_exception is not None,
        pending_reraise_exception=state.pending_reraise_exception is not None,
        write_event_count=len(state.write_events),
        detector_obligation_count=len(state.deferred_detector_issues),
        detector_obligation_keys=detector_obligation_digest(
            tuple(state.deferred_detector_issues),
        ),
        havoc_live_count=_state_havoc_live_count(state),
    )
    stable_id = capsule_id
    if stable_id is None:
        stable_id = (
            f"capsule:{state.path_id}:{state.pc}:{state.depth}:"
            f"{len(constraint_atom_ids)}:{branch_trace_length}"
        )

    return ObligationCapsule(
        capsule_id=stable_id,
        parent_id=parent_id,
        path_id=state.path_id,
        depth=state.depth,
        footprint=footprint,
        constraint_atom_ids=constraint_atom_ids,
        pending_constraint_count=state.pending_constraint_count,
        branch_trace_length=branch_trace_length,
        estimated_resident_units=_estimate_resident_units(state),
    )


def capsule_semantic_digest(capsule: ObligationCapsule) -> CapsuleDigest:
    """Return the deterministic VMState facts represented by ``capsule``."""
    return (
        capsule.path_id,
        capsule.depth,
        capsule.footprint.pc,
        capsule.footprint.state_structural_hash,
        capsule.footprint.stack_depth,
        capsule.footprint.local_names,
        capsule.footprint.global_names,
        capsule.footprint.memory_cell_count,
        capsule.footprint.active_exception,
        capsule.footprint.pending_reraise_exception,
        capsule.footprint.write_event_count,
        capsule.footprint.detector_obligation_count,
        capsule.footprint.detector_obligation_keys,
        capsule.footprint.unsupported_live_count,
        capsule.footprint.havoc_live_count,
        capsule.constraint_atom_ids,
        capsule.pending_constraint_count,
        capsule.branch_trace_length,
        capsule.estimated_resident_units,
    )


def state_shadow_digest(state: "VMState") -> CapsuleDigest:
    """Return the deterministic VMState facts required by phase-0 capsules."""
    constraint_atom_ids = state.path_constraints.sorted_constraint_hashes()
    return (
        state.path_id,
        state.depth,
        state.pc,
        state_structural_hash(state),
        len(state.stack),
        state.local_vars.sorted_keys(),
        state.global_vars.sorted_keys(),
        len(state.memory),
        state.active_exception is not None,
        state.pending_reraise_exception is not None,
        len(state.write_events),
        len(state.deferred_detector_issues),
        detector_obligation_digest(tuple(state.deferred_detector_issues)),
        0,
        _state_havoc_live_count(state),
        constraint_atom_ids,
        state.pending_constraint_count,
        len(state.branch_trace),
        _estimate_resident_units(state),
    )


def capsule_matches_state(capsule: ObligationCapsule, state: "VMState") -> bool:
    """Return whether ``capsule`` preserves the phase-0 facts read from ``state``."""
    return capsule_semantic_digest(capsule) == state_shadow_digest(state)


def collect_frontier_telemetry(capsules: "Iterable[ObligationCapsule]") -> FrontierTelemetry:
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


def _estimate_resident_units(state: "VMState") -> int:
    """Return a deterministic size proxy for migration telemetry."""
    return (
        len(state.stack)
        + len(state.local_vars)
        + len(state.global_vars)
        + len(state.memory)
        + len(state.path_constraints)
        + len(state.branch_trace)
        + len(state.deferred_detector_issues)
        + len(state.write_events)
    )


def _state_havoc_live_count(state: "VMState") -> int:
    """Return top-level havoc roots visible to frontier telemetry."""
    return havoc_root_count(
        (
            *state.stack,
            *state.local_vars.values(),
            *state.global_vars.values(),
            *state.memory.values(),
            *((state.active_exception,) if state.active_exception is not None else ()),
            *(
                (state.pending_reraise_exception,)
                if state.pending_reraise_exception is not None
                else ()
            ),
            *state.awaitable_results.values(),
        )
    )


def state_structural_hash(state: "VMState") -> int:
    """Return the VMState structural hash used by duplicate-capsule detection."""
    return state.hash_value()
