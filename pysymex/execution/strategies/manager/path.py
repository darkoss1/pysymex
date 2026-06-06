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
from collections.abc import Mapping
from typing import TYPE_CHECKING

from pysymex.core.graph.cig import ConstraintInteractionGraph
from pysymex.execution.frontier import (
    FrontierQueueEntry,
    FrontierRuntimeMode,
    FrontierWorkStore,
)
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    CegisRuntimeController,
    EvidenceApplicationPlan,
    EvidenceOutcome,
    ShadowDecisionEvaluation,
)
from pysymex.execution.scheduling.telemetry import SchedulerDecisionSource

from .pressure import (
    PressureCompactionPolicy,
    cold_compaction_state_ids,
    estimate_state_resident_units,
    runtime_native_priority,
)
from .scheduler_trace import SchedulerTraceMixin
from .stats import polar_manager_stats
from .types import PathManager, PrioritizedState

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class PolarCegisPathManager(SchedulerTraceMixin, PathManager["VMState"]):
    """Path manager that schedules exploration through the POLAR runtime queue."""

    ARM_POLAR_NATIVE = "polar-cegis-native"

    def __init__(
        self,
        cig: ConstraintInteractionGraph,
        deterministic: bool = False,
        random_seed: int = 42,
        frontier_runtime_mode: FrontierRuntimeMode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
        pressure_policy: PressureCompactionPolicy | None = None,
    ):
        """Initialize the native POLAR frontier queue.

        ``deterministic`` and ``random_seed`` are accepted for execution-config
        compatibility. The POLAR queue is deterministic by construction and
        uses insertion order to break equal-priority ties.
        """
        _ = deterministic
        _ = random_seed
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

    def add_state(self, state: "VMState", priority: float = 0.0) -> None:
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

    def get_next_state(self) -> "VMState | None":
        """Pop the next live state without applying heuristic pruning."""
        if len(self._frontier) == 0:
            return None
        if self._frontier_runtime_mode.certificate_pruning_enabled:
            self._apply_runtime_cegis_evidence()
            if len(self._frontier) == 0:
                return None
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

    def preview_shadow_cegis_frontier(
        self,
        active_budget: BudgetVector,
        *,
        memory_pressure: float = 0.0,
        solver_timeout_ms: int = 10000,
        unsat_core_timeout_ms: int = 5000,
    ) -> ShadowDecisionEvaluation:
        """Select and evaluate one live CEGIS shadow bid without mutating work."""
        return self._cegis_runtime.preview_shadow_frontier(
            self._frontier,
            active_budget,
            memory_pressure=memory_pressure,
            solver_timeout_ms=solver_timeout_ms,
            unsat_core_timeout_ms=unsat_core_timeout_ms,
        )

    def preview_evidence_outcome(self, outcome: EvidenceOutcome) -> EvidenceApplicationPlan:
        """Plan CEGIS owner outcome application without mutating the frontier."""
        return self._cegis_runtime.preview_evidence_outcome(self._frontier, outcome)

    def apply_evidence_outcome(self, outcome: EvidenceOutcome) -> int:
        """Remove queued states covered by a valid CEGIS owner outcome."""
        return self._cegis_runtime.apply_evidence_outcome(self._frontier, outcome)

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

    def _pop_runtime_native_state(self) -> "VMState | None":
        """Pop the next state from the POLAR runtime priority queue."""
        while self._heap_polar_native:
            entry = heapq.heappop(self._heap_polar_native)
            state_id = entry.state
            if state_id in self._frontier:
                return self._pop_state_with_scheduler_event(
                    state_id,
                    decision_source="polar_native",
                    priority=entry.priority,
                    path_decision=self.ARM_POLAR_NATIVE,
                    reason="highest-priority POLAR native state selected",
                )
        return None

    def _pop_first_live_state(self) -> "VMState | None":
        """Pop any remaining live state if the priority queue unexpectedly goes stale."""
        for state_id in sorted(self._frontier.live_state_ids):
            state = self._pop_state_with_scheduler_event(
                state_id,
                decision_source="first_live_fallback",
                priority=None,
                path_decision=self.ARM_POLAR_NATIVE,
                reason="native heap was stale; first live state selected",
            )
            if state is not None:
                return state
        return None

    def _pop_state_with_scheduler_event(
        self,
        state_id: int,
        *,
        decision_source: SchedulerDecisionSource,
        priority: float | None,
        path_decision: str,
        reason: str,
    ) -> "VMState | None":
        """Pop one live state and emit the corresponding scheduler event."""
        frontier_size_before = len(self._frontier)
        estimated_resident_units = self._resident_units_by_state_id.get(state_id)
        features = self._frontier.runtime_features.get(state_id)
        state = self._remove_state(state_id)
        if state is None:
            return None

        self._covered_pcs.update(state.visited_pcs)
        self._last_decisions["path"] = path_decision
        self._record_scheduler_event_for_state(
            action="select",
            decision_source=decision_source,
            state_id=state_id,
            state=state,
            features=features,
            frontier_size_before=frontier_size_before,
            frontier_size_after=len(self._frontier),
            branch_degree=self.cig.get_degree(state.pc),
            priority=priority,
            estimated_resident_units=(
                estimated_resident_units
                if estimated_resident_units is not None
                else estimate_state_resident_units(state)
            ),
            reason=reason,
        )
        return state

    def _compact_frontier_under_pressure(self) -> None:
        """Compact a bounded cold batch when resident frontier pressure is high."""
        if not self._frontier_runtime_mode.certificate_pruning_enabled:
            return
        if not self._pressure_policy.should_check(
            len(self._frontier),
            self._estimated_resident_units_total,
        ):
            return

        self._pressure_compaction_trigger_count += 1
        for state_id in cold_compaction_state_ids(
            self._heap_polar_native,
            self._frontier.live_state_ids,
            self._resident_units_by_state_id,
            batch_size=self._pressure_policy.batch_size,
        ):
            if self._request_state_compaction(state_id):
                self._pressure_compaction_count += 1

    def _request_state_compaction(self, state_id: int) -> bool:
        """Compact one state and update resident-unit pressure accounting."""
        decision = self._frontier.request_compaction(state_id)
        if not decision.can_compact:
            return False
        self._drop_resident_units(state_id)
        return True

    def _apply_runtime_cegis_evidence(self) -> None:
        """Apply exact runtime CEGIS owner evidence before normal path selection."""
        self._cegis_runtime.apply_runtime_evidence(self._frontier)

    def _pop_runtime_cegis_state(self) -> "VMState | None":
        """Pop the next runtime state selected by deterministic CEGIS execute bids."""
        state_id = self._cegis_runtime.select_runtime_execution_state_id(self._frontier)
        if state_id is None:
            return None
        return self._pop_state_with_scheduler_event(
            state_id,
            decision_source="cegis_execute",
            priority=None,
            path_decision="cegis-execute",
            reason="detector-obligation state selected by CEGIS runtime",
        )

    def _remove_state(self, state_id: int) -> "VMState | None":
        """Pop and materialize one live state plus its shadow diagnostics."""
        self._drop_resident_units(state_id)
        return self._frontier.pop_materialized(state_id)

    def _drop_resident_units(self, state_id: int) -> None:
        """Remove resident-memory accounting for a no-longer-resident state."""
        resident_units = self._resident_units_by_state_id.pop(state_id, None)
        if resident_units is None:
            return
        self._estimated_resident_units_total = max(
            0,
            self._estimated_resident_units_total - resident_units,
        )


AdaptivePathManager = PolarCegisPathManager
