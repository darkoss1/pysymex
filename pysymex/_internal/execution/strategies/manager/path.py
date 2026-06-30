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

"""POLAR/CEGIS path manager.

The manager owns frontier ordering only. It may prioritize live work using cheap
POLAR runtime features, but feasible-path removal stays owned by exact CEGIS
evidence and solver-backed application plans.
"""

from __future__ import annotations

import heapq
import itertools
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.runtime.features import estimate_state_resident_units
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
from pysymex._internal.execution.scheduling.cegis.runtime.controller import CegisRuntimeController

from .cegis import PolarCegisManagerMixin
from .compaction import PolarPressureCompactionMixin
from .pressure import (
    PressureCompactionPolicy,
    runtime_native_priority,
)
from .scheduler.trace import SchedulerTraceMixin
from .selection import PolarSelectionMixin
from .stats import polar_manager_stats
from .types import PathManager, PrioritizedState

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.entries import FrontierQueueEntry


class PolarCegisPathManager(
    PolarSelectionMixin,
    PolarCegisManagerMixin,
    PolarPressureCompactionMixin,
    SchedulerTraceMixin,
    PathManager["VMState"],
):
    """Path manager that schedules exploration through the POLAR runtime queue."""

    ARM_POLAR_NATIVE = "polar-cegis-native"

    def __init__(
        self,
        cig: ConstraintInteractionGraph,
        frontier_runtime_mode: FrontierRuntimeMode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
        pressure_policy: PressureCompactionPolicy | None = None,
    ) -> None:
        """Initialize the native POLAR frontier queue."""
        self.cig = cig
        self._frontier_runtime_mode = frontier_runtime_mode
        self._pressure_policy = pressure_policy or PressureCompactionPolicy()
        self._frontier = FrontierWorkStore(
            frontier_runtime_mode,
            eager_shadow_capsules=frontier_runtime_mode is FrontierRuntimeMode.POLAR_CEGIS_SHADOW,
        )
        self._cegis_runtime = CegisRuntimeController()
        self._counter = itertools.count()
        self._heap_polar_native: list[PrioritizedState[int]] = []
        self._resident_units_by_state_id: dict[int, int] = {}
        self._estimated_resident_units_total = 0
        self._pressure_compaction_count = 0
        self._pressure_compaction_trigger_count = 0
        self._covered_pcs: set[int] = set()
        self._last_decisions: dict[str, str] = {}
        self._total_rewards = 0.0
        self._init_scheduler_event_observers()

    @property
    def states(self) -> Mapping[int, FrontierQueueEntry]:
        """Return live queued frontier entries for diagnostics and tests."""
        return self._frontier.entries

    def add_state(self, state: VMState, priority: float = 0.0) -> None:
        """Enqueue ``state`` into the native POLAR priority queue."""
        _ = priority
        frontier_size_before = len(self._frontier)
        count = next(self._counter)
        state_id = count
        branch_degree = self.cig.get_degree(state.pc)
        estimated_resident_units = estimate_state_resident_units(state)
        self._resident_units_by_state_id[state_id] = estimated_resident_units
        self._estimated_resident_units_total += estimated_resident_units
        self._frontier.add_state(state_id, state)
        runtime_priority = runtime_native_priority(
            state=state,
            branch_degree=branch_degree,
            features=self._frontier.runtime_features.get(state_id),
            estimated_resident_units=estimated_resident_units,
        )
        heapq.heappush(self._heap_polar_native, PrioritizedState(runtime_priority, count, state_id))
        if self._scheduler_event_observers:
            self._record_scheduler_event_for_state(
                action="enqueue",
                decision_source="polar_native",
                state_id=state_id,
                state=state,
                features=self._frontier.runtime_features.get(state_id),
                frontier_size_before=frontier_size_before,
                frontier_size_after=len(self._frontier),
                branch_degree=branch_degree,
                priority=runtime_priority,
                estimated_resident_units=estimated_resident_units,
                reason="state admitted to POLAR native frontier",
            )
        self._compact_frontier_under_pressure()

    def get_next_state(self) -> VMState | None:
        """Pop the next live state without applying heuristic pruning."""
        if len(self._frontier) == 0:
            return None
        if self._frontier_runtime_mode.certificate_pruning_enabled:
            state = self._pop_runtime_cegis_state()
            if state is not None:
                return state

        state = self._pop_runtime_native_state()
        if state is not None:
            return state
        return self._pop_first_live_state()

    def is_empty(self) -> bool:
        """Return whether no queued frontier work remains."""
        return len(self._frontier) == 0

    def size(self) -> int:
        """Return the number of pending states."""
        return len(self._frontier)

    def compact_runtime_frontier(self) -> int:
        """Compact all live runtime frontier entries that have exact checkpoints."""
        if not self._frontier_runtime_mode.certificate_pruning_enabled:
            return 0
        compacted_count = 0
        for state_id in tuple(self._frontier.live_state_ids):
            if self._request_state_compaction(state_id):
                compacted_count += 1
        return compacted_count

    def record_reward(self, reward: float) -> None:
        """Record aggregate reward telemetry for execution diagnostics."""
        self._total_rewards += reward

    def get_stats(self) -> dict[str, object]:
        """Return bounded worklist diagnostics."""
        return polar_manager_stats(
            frontier=self._frontier,
            cegis_runtime=self._cegis_runtime,
            frontier_runtime_mode=self._frontier_runtime_mode,
            path_policy=self.ARM_POLAR_NATIVE,
            path_decisions=self._last_decisions,
            covered_pc_count=len(self._covered_pcs),
            total_rewards=self._total_rewards,
            estimated_resident_units_total=self._estimated_resident_units_total,
            pressure_compaction_count=self._pressure_compaction_count,
            pressure_compaction_trigger_count=self._pressure_compaction_trigger_count,
        )


AdaptivePathManager = PolarCegisPathManager
