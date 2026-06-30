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

"""Shadow reconstruction checkpoints for POLAR frontier validation.

Checkpoints keep a compact snapshot behind a POLAR capsule so reconstruction
parity can be tested before compact runtime queueing is allowed. They support
solver-owned certificate evaluation in runtime CEGIS mode, but they do not
schedule work or remove live states directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoint.snapshot.digest import snapshot_digest
from pysymex._internal.execution.frontier.checkpoint.snapshot.record import FrontierStateSnapshot
from pysymex._internal.execution.frontier.evidence import detector_obligation_digest
from pysymex._internal.execution.frontier.obligations.capsules import build_shadow_capsule
from pysymex._internal.execution.frontier.obligations.digests import capsule_semantic_digest

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.obligations.types import (
        CapsuleDigest,
        ObligationCapsule,
    )


class FrontierReconstructionStatus(Enum):
    """Outcome of a shadow checkpoint reconstruction attempt."""

    EXACT = "exact"
    DIGEST_MISMATCH = "digest_mismatch"
    SPILL_FORMAT_MISMATCH = "spill_format_mismatch"


@dataclass(frozen=True, slots=True)
class FrontierReconstructionResult:
    """Result of reconstructing a VMState from a shadow checkpoint."""

    status: FrontierReconstructionStatus
    capsule_id: str
    reconstructed_state: VMState | None = None
    expected_digest: CapsuleDigest | None = None
    actual_digest: CapsuleDigest | None = None

    @property
    def is_exact(self) -> bool:
        """Return whether reconstruction produced an exact state snapshot."""
        return self.status is FrontierReconstructionStatus.EXACT


@dataclass(frozen=True, slots=True)
class FrontierCheckpoint:
    """Stored compact state snapshot used to validate future POLAR reconstruction."""

    capsule: ObligationCapsule
    _snapshot: FrontierStateSnapshot

    @property
    def snapshot(self) -> FrontierStateSnapshot:
        """Return the compact snapshot owned by this checkpoint."""
        return self._snapshot

    def snapshot_matches_capsule(self) -> bool:
        """Return whether the stored snapshot still matches the capsule digest."""
        return capsule_semantic_digest(self.capsule) == self._snapshot.digest() and (
            _capsule_digest_fields_match_snapshot(self.capsule, self._snapshot)
        )

    def path_constraints(self) -> tuple[z3.BoolRef, ...]:
        """Return checkpointed path constraints without materializing a VMState."""
        return self._snapshot.path_constraints

    def structurally_matches(self, other: FrontierCheckpoint) -> bool:
        """Return whether two live checkpoints are exact structural duplicates.

        This is stricter than matching capsule digests. Digests and
        ``VMState.hash_value()`` are useful indexes, but the dominance owner
        must recheck exact checkpoint facts before certifying removal.
        """
        return (
            self.snapshot_matches_capsule()
            and other.snapshot_matches_capsule()
            and self._snapshot.structurally_matches(other._snapshot)
        )

    def reconstruct(self) -> FrontierReconstructionResult:
        """Return a parity VMState when the compact snapshot still matches the capsule digest."""
        expected_digest = capsule_semantic_digest(self.capsule)
        actual_digest = snapshot_digest(self._snapshot)
        if not self.snapshot_matches_capsule():
            return FrontierReconstructionResult(
                status=FrontierReconstructionStatus.DIGEST_MISMATCH,
                capsule_id=self.capsule.capsule_id,
                expected_digest=expected_digest,
                actual_digest=actual_digest,
            )
        return FrontierReconstructionResult(
            status=FrontierReconstructionStatus.EXACT,
            capsule_id=self.capsule.capsule_id,
            reconstructed_state=self._snapshot.reconstruct(),
            expected_digest=expected_digest,
            actual_digest=actual_digest,
        )


def build_frontier_checkpoint(
    state: VMState,
    *,
    capsule_id: str | None = None,
    parent_id: str | None = None,
) -> FrontierCheckpoint:
    """Build a compact shadow checkpoint from ``state`` without mutating the active path."""
    capsule = build_shadow_capsule(state, capsule_id=capsule_id, parent_id=parent_id)
    return FrontierCheckpoint(
        capsule=capsule,
        _snapshot=FrontierStateSnapshot.from_state(state),
    )


def _capsule_digest_fields_match_snapshot(
    capsule: ObligationCapsule,
    snapshot: FrontierStateSnapshot,
) -> bool:
    footprint = capsule.footprint
    return (
        capsule.path_id == snapshot.path_id
        and capsule.depth == snapshot.depth
        and footprint.pc == snapshot.pc
        and footprint.state_structural_hash == snapshot.state_structural_hash
        and footprint.stack_depth == len(snapshot.stack)
        and footprint.local_names == tuple(name for name, _ in snapshot.local_vars)
        and footprint.global_names == tuple(name for name, _ in snapshot.global_vars)
        and footprint.memory_cell_count == len(snapshot.memory)
        and footprint.active_exception == (snapshot.active_exception is not None)
        and footprint.pending_reraise_exception
        == (snapshot.pending_reraise_exception is not None)
        and footprint.write_event_count == len(snapshot.write_events)
        and footprint.detector_obligation_count == len(snapshot.deferred_detector_issues)
        and footprint.detector_obligation_keys
        == detector_obligation_digest(snapshot.deferred_detector_issues)
        and footprint.unsupported_live_count == 0
        and footprint.havoc_live_count == snapshot.havoc_live_count
        and capsule.constraint_atom_ids == snapshot.constraint_atom_ids
        and capsule.pending_constraint_count == snapshot.pending_constraint_count
        and capsule.branch_trace_length == len(snapshot.branch_trace)
        and capsule.estimated_resident_units == snapshot.estimated_resident_units
    )
