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

"""Live frontier work storage for POLAR queue payloads.

This module owns the mapping from scheduler state IDs to frontier payloads,
shadow capsules, and reconstruction checkpoints. Path managers may schedule
integer IDs, but compact state materialization and POLAR telemetry live here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex.execution.frontier.checkpoints import FrontierCheckpoint, build_frontier_checkpoint
from pysymex.execution.frontier.compaction import (
    FrontierCompactionDecision,
    FrontierCompactionStatus,
)
from pysymex.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
    build_frontier_queue_entry,
    materialize_frontier_queue_entry,
)
from pysymex.execution.frontier.modes import FrontierRuntimeMode
from pysymex.execution.frontier.obligations import (
    FrontierTelemetry,
    ObligationCapsule,
    build_shadow_capsule,
    capsule_semantic_digest,
    collect_frontier_telemetry,
)
from pysymex.execution.frontier.spill import FrontierSpillDecision, FrontierSpillPolicy
from pysymex.execution.frontier.spill import (
    delete_spilled_frontier_entry,
    materialize_spilled_frontier_entry,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

__all__ = [
    "FrontierWorkStore",
    "FrontierWorkStoreStats",
]


@dataclass(frozen=True, slots=True)
class FrontierWorkStoreStats:
    """Snapshot of live frontier storage and POLAR telemetry counters."""

    enabled: bool
    compact_queueing_enabled: bool
    checkpoint_count: int
    compacted_entry_count: int
    spilled_entry_count: int
    capsule_digest_mismatch_count: int
    reconstruction_mismatch_count: int
    compaction_denied_count: int
    spill_denied_count: int
    telemetry: FrontierTelemetry


@dataclass(frozen=True, slots=True)
class FrontierRuntimeFeatures:
    """Cheap live-state facts used for default runtime scheduling.

    These features are not proof artifacts. They may rank resident work for
    execution, but CEGIS removal still requires full capsules/checkpoints.
    """

    capsule_id: str
    detector_obligation_count: int
    pending_constraint_count: int
    estimated_resident_units: int
    unsupported_live_count: int = 0
    havoc_live_count: int = 0


class FrontierWorkStore:
    """Own live frontier payloads and shadow POLAR state for scheduler IDs."""

    def __init__(
        self,
        runtime_mode: FrontierRuntimeMode,
        *,
        eager_shadow_capsules: bool = True,
    ) -> None:
        self._runtime_mode = runtime_mode
        self._eager_shadow_capsules = eager_shadow_capsules
        self._entries: dict[int, FrontierQueueEntry] = {}
        self._capsules: dict[int, ObligationCapsule] = {}
        self._checkpoints: dict[int, FrontierCheckpoint] = {}
        self._runtime_features: dict[int, FrontierRuntimeFeatures] = {}
        self._compacted_entry_count = 0
        self._capsule_digest_mismatch_count = 0
        self._reconstruction_mismatch_count = 0
        self._compaction_denied_count = 0
        self._spill_denied_count = 0
        self._selection_version = 0
        self._capsule_coverage_version = -1

    @property
    def entries(self) -> Mapping[int, FrontierQueueEntry]:
        """Return queued payload entries keyed by scheduler state ID."""
        return self._entries

    @property
    def capsules(self) -> Mapping[int, ObligationCapsule]:
        """Return live shadow capsules keyed by scheduler state ID."""
        return self._capsules

    @property
    def checkpoints(self) -> Mapping[int, FrontierCheckpoint]:
        """Return live reconstruction checkpoints keyed by scheduler state ID."""
        return self._checkpoints

    @property
    def runtime_features(self) -> Mapping[int, FrontierRuntimeFeatures]:
        """Return cheap live scheduling facts keyed by scheduler state ID."""
        return self._runtime_features

    @property
    def live_state_ids(self) -> Iterable[int]:
        """Return live scheduler state IDs."""
        return self._entries.keys()

    @property
    def selection_version(self) -> int:
        """Return the frontier version for cached live-state selection."""
        return self._selection_version

    def __contains__(self, state_id: int) -> bool:
        """Return whether ``state_id`` is live in the frontier."""
        return state_id in self._entries

    def __len__(self) -> int:
        """Return the number of live queued frontier entries."""
        return len(self._entries)

    def add_state(self, state_id: int, state: "VMState") -> None:
        """Record a queued state under ``state_id`` according to the active mode."""
        checkpoint = self._build_checkpoint_if_enabled(state_id, state)
        if self._runtime_mode.runtime_replacement_enabled and state.deferred_detector_issues:
            self._runtime_features[state_id] = self._build_runtime_features(state_id, state)
        self._entries[state_id] = build_frontier_queue_entry(
            state,
            checkpoint=checkpoint,
            compact_queueing=self._runtime_mode.compact_queueing_enabled,
        )
        self._mark_selection_inputs_changed()

    def pop_materialized(self, state_id: int) -> "VMState | None":
        """Remove and materialize one live queued state."""
        entry = self._entries.pop(state_id, None)
        self._discard_shadow_state(state_id)
        if entry is None:
            return None
        try:
            if entry.is_spilled:
                materialized_state = materialize_spilled_frontier_entry(entry)
                delete_spilled_frontier_entry(entry)
                return materialized_state
            return materialize_frontier_queue_entry(entry)
        except FrontierMaterializationError:
            self._reconstruction_mismatch_count += 1
            raise

    def discard(self, state_id: int) -> None:
        """Remove one live queued state without materializing compact payloads."""
        entry = self._entries.pop(state_id, None)
        if entry is not None:
            delete_spilled_frontier_entry(entry)
        self._discard_shadow_state(state_id)

    def request_compaction(self, state_id: int) -> FrontierCompactionDecision:
        """Replace one resident entry with an exact in-memory checkpoint when possible."""
        entry = self._entries.get(state_id)
        if entry is None:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.NOT_LIVE,
                explanation="frontier entry is not live",
            )
            self._compaction_denied_count += 1
            return decision
        if entry.is_compact:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.ALREADY_COMPACT,
                explanation="frontier entry is already compact",
            )
            self._compaction_denied_count += 1
            return decision

        checkpoint = self.ensure_checkpoint(state_id)
        if checkpoint is None:
            decision = FrontierCompactionDecision(
                status=FrontierCompactionStatus.CHECKPOINT_UNAVAILABLE,
                explanation="exact checkpoint is not available",
            )
            self._compaction_denied_count += 1
            return decision

        compacted_entry = FrontierQueueEntry(checkpoint=checkpoint)
        self._entries[state_id] = compacted_entry
        self._compacted_entry_count += 1
        return FrontierCompactionDecision(
            status=FrontierCompactionStatus.COMPACTED,
            explanation="frontier entry compacted to an exact checkpoint",
            compacted_entry=compacted_entry,
        )

    def request_spill(
        self,
        state_id: int,
        policy: FrontierSpillPolicy | None = None,
    ) -> FrontierSpillDecision:
        """Evaluate and apply a safe spill request for one live entry."""
        entry = self._entries.get(state_id)
        active_policy = policy if policy is not None else FrontierSpillPolicy()
        if entry is None:
            decision = active_policy.evaluate_missing()
        else:
            spill_entry = entry
            if (
                active_policy.filesystem_spill_enabled
                and self._runtime_mode.certificate_pruning_enabled
                and not entry.is_compact
            ):
                checkpoint = self.ensure_checkpoint(state_id)
                if checkpoint is not None:
                    spill_entry = FrontierQueueEntry(checkpoint=checkpoint)
            decision = active_policy.evaluate(spill_entry, state_id=state_id)
        if decision.can_spill and decision.spilled_entry is not None:
            self._entries[state_id] = decision.spilled_entry
            self._checkpoints.pop(state_id, None)
        else:
            self._spill_denied_count += 1
        return decision

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
            state = materialize_frontier_queue_entry(entry)
        except FrontierMaterializationError:
            self._reconstruction_mismatch_count += 1
            return None

        checkpoint = build_frontier_checkpoint(state, capsule_id=f"path:{state_id}")
        capsule = self._capsules.get(state_id)
        if capsule is not None and capsule_semantic_digest(capsule) != capsule_semantic_digest(
            checkpoint.capsule
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
            state = materialize_frontier_queue_entry(entry)
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

    def collect_stats(self) -> FrontierWorkStoreStats:
        """Return aggregate live frontier telemetry for result diagnostics."""
        telemetry = collect_frontier_telemetry(self._capsules.values())
        return FrontierWorkStoreStats(
            enabled=self._runtime_mode.shadow_telemetry_enabled,
            compact_queueing_enabled=self._runtime_mode.compact_queueing_enabled,
            checkpoint_count=len(self._checkpoints),
            compacted_entry_count=self._compacted_entry_count,
            spilled_entry_count=sum(entry.is_spilled for entry in self._entries.values()),
            capsule_digest_mismatch_count=self._capsule_digest_mismatch_count,
            reconstruction_mismatch_count=self._reconstruction_mismatch_count,
            compaction_denied_count=self._compaction_denied_count,
            spill_denied_count=self._spill_denied_count,
            telemetry=telemetry,
        )

    def _build_checkpoint_if_enabled(
        self,
        state_id: int,
        state: "VMState",
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

    def _discard_shadow_state(self, state_id: int) -> None:
        """Discard shadow records for a scheduler state ID."""
        self._checkpoints.pop(state_id, None)
        self._capsules.pop(state_id, None)
        self._runtime_features.pop(state_id, None)
        self._mark_selection_inputs_changed()

    def _mark_selection_inputs_changed(self) -> None:
        """Invalidate caches derived from live frontier selection inputs."""
        self._selection_version += 1

    def _build_runtime_features(
        self,
        state_id: int,
        state: "VMState",
    ) -> FrontierRuntimeFeatures:
        """Build low-cost scheduling features without capsule digests."""
        return FrontierRuntimeFeatures(
            capsule_id=f"path:{state_id}",
            detector_obligation_count=len(state.deferred_detector_issues),
            pending_constraint_count=state.pending_constraint_count,
            estimated_resident_units=max(
                1,
                len(state.stack)
                + len(state.local_vars)
                + len(state.global_vars)
                + len(state.memory)
                + len(state.path_constraints)
                + len(state.branch_trace)
                + len(state.deferred_detector_issues)
                + len(state.write_events),
            ),
        )
