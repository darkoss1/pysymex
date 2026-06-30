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

"""Semantic digests for frontier obligation capsules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.evidence import detector_obligation_digest
from pysymex._internal.execution.frontier.obligations.residency import (
    estimate_resident_units,
    state_havoc_live_count,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.obligations.types import (
        CapsuleDigest,
        ObligationCapsule,
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


def state_shadow_digest(state: VMState) -> CapsuleDigest:
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
        state_havoc_live_count(state),
        constraint_atom_ids,
        state.pending_constraint_count,
        len(state.branch_trace),
        estimate_resident_units(state),
    )


def capsule_matches_state(capsule: ObligationCapsule, state: VMState) -> bool:
    """Return whether ``capsule`` preserves the phase-0 facts read from ``state``."""
    return capsule_semantic_digest(capsule) == state_shadow_digest(state)


def state_structural_hash(state: VMState) -> int:
    """Return the VMState structural hash used by duplicate-capsule detection."""
    return state.hash_value()
