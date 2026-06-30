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

"""Concrete live frontier work store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.store.artifacts import WorkStoreArtifactMixin
from pysymex._internal.execution.frontier.store.lifecycle import WorkStoreLifecycleMixin
from pysymex._internal.execution.frontier.store.requests import WorkStoreRequestMixin
from pysymex._internal.execution.frontier.store.statistics import WorkStoreStatsMixin

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.frontier.entries import FrontierQueueEntry
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule
    from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures


class FrontierWorkStore(
    WorkStoreLifecycleMixin,
    WorkStoreArtifactMixin,
    WorkStoreStatsMixin,
    WorkStoreRequestMixin,
):
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
