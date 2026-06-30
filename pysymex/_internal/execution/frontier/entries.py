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

"""Queued frontier entries for POLAR runtime payloads.

This module owns the payload boundary between the scheduler's integer work IDs
and the executable ``VMState`` objects needed by the VM. Resident queueing keeps
live states here; checkpoint and spilled entries are explicit compact payloads
used only when proof materialization or spill policy requires them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.checkpoints import (
        FrontierCheckpoint,
        FrontierReconstructionStatus,
    )


class FrontierMaterializationError(RuntimeError):
    """Raised when a compact queued checkpoint cannot reconstruct exactly."""

    def __init__(
        self,
        *,
        capsule_id: str,
        status: FrontierReconstructionStatus,
    ) -> None:
        self.capsule_id = capsule_id
        self.status = status
        super().__init__(
            f"frontier checkpoint reconstruction failed for {capsule_id}: {status.value}",
        )


@dataclass(frozen=True, slots=True)
class FrontierQueueEntry:
    """One queued frontier payload owned by the native frontier layer."""

    state: VMState | None = None
    checkpoint: FrontierCheckpoint | None = None
    spilled_checkpoint_path: Path | None = None

    def __post_init__(self) -> None:
        """Reject entries that do not contain exactly one payload kind."""
        has_state = self.state is not None
        has_checkpoint = self.checkpoint is not None
        has_spill = self.spilled_checkpoint_path is not None
        if (has_state + has_checkpoint + has_spill) != 1:
            msg = "frontier queue entry must contain exactly one payload"
            raise ValueError(msg)

    @property
    def is_compact(self) -> bool:
        """Return whether the entry stores a compact checkpoint."""
        return self.checkpoint is not None or self.spilled_checkpoint_path is not None

    @property
    def is_spilled(self) -> bool:
        """Return whether the entry stores an external spilled checkpoint."""
        return self.spilled_checkpoint_path is not None


def build_frontier_queue_entry(
    state: VMState,
    *,
    checkpoint: FrontierCheckpoint | None,
    compact_queueing: bool,
) -> FrontierQueueEntry:
    """Build the queued payload for ``state`` under the active frontier mode."""
    if not compact_queueing:
        return FrontierQueueEntry(state=state)
    if checkpoint is None:
        msg = "compact frontier queueing requires a checkpoint"
        raise ValueError(msg)
    return FrontierQueueEntry(checkpoint=checkpoint)


def realize_frontier_queue_entry(entry: FrontierQueueEntry) -> VMState:
    """Return an executable VMState from a direct or compact queued entry."""
    if entry.state is not None:
        return entry.state

    checkpoint = entry.checkpoint
    if checkpoint is None:
        if entry.spilled_checkpoint_path is not None:
            msg = "spilled frontier entries must be materialized by the spill policy"
            raise ValueError(msg)
        msg = "frontier queue entry has no payload"
        raise ValueError(msg)

    reconstruction = checkpoint.reconstruct()
    if reconstruction.is_exact and reconstruction.reconstructed_state is not None:
        return reconstruction.reconstructed_state
    raise FrontierMaterializationError(
        capsule_id=checkpoint.capsule.capsule_id,
        status=reconstruction.status,
    )
