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

"""Lazy checkpoint and capsule materialization for frontier work storage."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoints import (
    FrontierCheckpoint,
    build_frontier_checkpoint,
)
from pysymex._internal.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
    realize_frontier_queue_entry,
)
from pysymex._internal.execution.frontier.obligations.capsules import build_shadow_capsule
from pysymex._internal.execution.frontier.obligations.digests import capsule_semantic_digest

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule
    from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures

    class WorkStoreArtifactContract:
        """Static surface required by frontier artifact mixins."""

        _runtime_mode: FrontierRuntimeMode
        _eager_shadow_capsules: bool
        _entries: dict[int, FrontierQueueEntry]
        _capsules: dict[int, ObligationCapsule]
        _checkpoints: dict[int, FrontierCheckpoint]
        _runtime_features: dict[int, FrontierRuntimeFeatures]
        _capsule_digest_mismatch_count: int
        _reconstruction_mismatch_count: int
        _selection_version: int
        _capsule_coverage_version: int

        def _mark_selection_inputs_changed(self) -> None:
            """Invalidate live frontier selection inputs."""
            ...

else:

    class WorkStoreArtifactContract:
        """Runtime placeholder for the type-checking-only artifact mixin surface."""


class WorkStoreArtifactMixin(WorkStoreArtifactContract):
    """Build and validate shadow frontier artifacts for live work."""

    def ensure_checkpoint(self, state_id: int) -> FrontierCheckpoint | None:
        """Return a live checkpoint for ``state_id``, building it lazily when needed."""
        checkpoint = self._checkpoints.get(state_id)
        if checkpoint is not None:
            return checkpoint
        if not self._runtime_mode.shadow_telemetry_enabled:
            return None

        entry = self._entries.get(state_id)
        if entry is None or entry.is_spilled:
            return None
        try:
            state = realize_frontier_queue_entry(entry)
        except FrontierMaterializationError:
            self._reconstruction_mismatch_count += 1
            return None

        checkpoint = build_frontier_checkpoint(state, capsule_id=f"path:{state_id}")
        capsule = self._capsules.get(state_id)
        if capsule is not None and capsule_semantic_digest(capsule) != capsule_semantic_digest(
            checkpoint.capsule,
        ):
            self._capsule_digest_mismatch_count += 1
            return None

        self._checkpoints[state_id] = checkpoint
        self._capsules[state_id] = checkpoint.capsule
        self._mark_selection_inputs_changed()
        return checkpoint

    def ensure_capsule(self, state_id: int) -> ObligationCapsule | None:
        """Return a live shadow capsule, building it lazily when possible."""
        capsule = self._capsules.get(state_id)
        if capsule is not None:
            return capsule
        if not self._runtime_mode.shadow_telemetry_enabled:
            return None

        entry = self._entries.get(state_id)
        if entry is None or entry.is_spilled:
            return None
        try:
            state = realize_frontier_queue_entry(entry)
        except FrontierMaterializationError:
            self._reconstruction_mismatch_count += 1
            return None

        capsule = build_shadow_capsule(state, capsule_id=f"path:{state_id}")
        self._capsules[state_id] = capsule
        self._mark_selection_inputs_changed()
        return capsule

    def ensure_capsules_for_live_states(self) -> None:
        """Build missing capsules for all currently resident live states."""
        if self._capsule_coverage_version == self._selection_version:
            return
        if not self._runtime_mode.shadow_telemetry_enabled:
            self._capsule_coverage_version = self._selection_version
            return

        coverage_complete = True
        for state_id, entry in self._entries.items():
            if state_id in self._capsules or entry.is_spilled:
                continue
            if self.ensure_capsule(state_id) is None:
                coverage_complete = False

        if coverage_complete:
            self._capsule_coverage_version = self._selection_version

    def _build_checkpoint_if_enabled(
        self,
        state_id: int,
        state: VMState,
    ) -> FrontierCheckpoint | None:
        """Build and index the frontier artifact required by the active mode."""
        if not self._runtime_mode.shadow_telemetry_enabled:
            return None
        if not self._eager_shadow_capsules and not self._runtime_mode.compact_queueing_enabled:
            return None
        if not self._runtime_mode.compact_queueing_enabled:
            self._capsules[state_id] = build_shadow_capsule(state, capsule_id=f"path:{state_id}")
            return None

        checkpoint = build_frontier_checkpoint(state, capsule_id=f"path:{state_id}")
        capsule = checkpoint.capsule
        self._checkpoints[state_id] = checkpoint
        self._capsules[state_id] = capsule
        return checkpoint
