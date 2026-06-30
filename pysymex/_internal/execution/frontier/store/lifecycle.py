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

"""Live frontier entry mutation and cleanup."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
    build_frontier_queue_entry,
    realize_frontier_queue_entry,
)
from pysymex._internal.execution.frontier.runtime.features import (
    FrontierRuntimeFeatures,
    build_frontier_runtime_features,
)
from pysymex._internal.execution.frontier.spill.codec.files import delete_spilled_frontier_entry
from pysymex._internal.execution.frontier.spill.decode.entry import (
    realize_spilled_frontier_entry,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule

    class WorkStoreLifecycleContract:
        """Static surface required by frontier lifecycle mixins."""

        _runtime_mode: FrontierRuntimeMode
        _entries: dict[int, FrontierQueueEntry]
        _capsules: dict[int, ObligationCapsule]
        _checkpoints: dict[int, FrontierCheckpoint]
        _runtime_features: dict[int, FrontierRuntimeFeatures]
        _reconstruction_mismatch_count: int
        _selection_version: int

        def _build_checkpoint_if_enabled(
            self,
            state_id: int,
            state: VMState,
        ) -> FrontierCheckpoint | None:
            """Build the checkpoint required by active frontier mode."""
            ...

else:

    class WorkStoreLifecycleContract:
        """Runtime placeholder for the type-checking-only lifecycle mixin surface."""


class WorkStoreLifecycleMixin(WorkStoreLifecycleContract):
    """Mutate live frontier entries and synchronized shadow state."""

    def add_state(self, state_id: int, state: VMState) -> None:
        """Record a queued state under ``state_id`` according to the active mode."""
        checkpoint = self._build_checkpoint_if_enabled(state_id, state)
        if self._runtime_mode.certificate_pruning_enabled and state.deferred_detector_issues:
            self._runtime_features[state_id] = build_frontier_runtime_features(state_id, state)
        self._entries[state_id] = build_frontier_queue_entry(
            state,
            checkpoint=checkpoint,
            compact_queueing=self._runtime_mode.compact_queueing_enabled,
        )
        self._mark_selection_inputs_changed()

    def pop_materialized(self, state_id: int) -> VMState | None:
        """Remove and materialize one live queued state."""
        entry = self._entries.pop(state_id, None)
        self._discard_shadow_state(state_id)
        if entry is None:
            return None
        try:
            if entry.is_spilled:
                materialized_state = realize_spilled_frontier_entry(entry)
                delete_spilled_frontier_entry(entry)
                return materialized_state
            return realize_frontier_queue_entry(entry)
        except FrontierMaterializationError:
            self._reconstruction_mismatch_count += 1
            raise

    def discard(self, state_id: int) -> None:
        """Remove one live queued state without materializing compact payloads."""
        entry = self._entries.pop(state_id, None)
        if entry is not None:
            delete_spilled_frontier_entry(entry)
        self._discard_shadow_state(state_id)

    def _discard_shadow_state(self, state_id: int) -> None:
        """Discard shadow records for a scheduler state ID."""
        self._checkpoints.pop(state_id, None)
        self._capsules.pop(state_id, None)
        self._runtime_features.pop(state_id, None)
        self._mark_selection_inputs_changed()

    def _mark_selection_inputs_changed(self) -> None:
        """Invalidate caches derived from live frontier selection inputs."""
        self._selection_version += 1
