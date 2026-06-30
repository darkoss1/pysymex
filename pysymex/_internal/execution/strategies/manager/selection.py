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

"""Live-state selection and removal helpers for POLAR path managers."""

from __future__ import annotations

import heapq
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.runtime.features import estimate_state_resident_units

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.runtime.features import FrontierRuntimeFeatures
    from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
    from pysymex._internal.execution.scheduling.telemetry import (
        SchedulerAction,
        SchedulerDecisionSource,
        SchedulerEvent,
    )
    from pysymex._internal.execution.strategies.manager.types import PrioritizedState


class PolarSelectionMixin:
    """Selection and removal operations for live POLAR frontier states."""

    if TYPE_CHECKING:
        cig: ConstraintInteractionGraph
        _frontier: FrontierWorkStore
        _heap_polar_native: list[PrioritizedState[int]]
        _resident_units_by_state_id: dict[int, int]
        _estimated_resident_units_total: int
        _covered_pcs: set[int]
        _last_decisions: dict[str, str]
        _scheduler_event_observers: list[Callable[[SchedulerEvent], None]]

        def _record_scheduler_event_for_state(
            self,
            *,
            action: SchedulerAction,
            decision_source: SchedulerDecisionSource,
            state_id: int,
            state: VMState,
            features: FrontierRuntimeFeatures | None,
            frontier_size_before: int,
            frontier_size_after: int,
            branch_degree: int | None,
            priority: float | None,
            estimated_resident_units: int,
            reason: str,
        ) -> None: ...

    def _pop_runtime_native_state(self) -> VMState | None:
        """Pop the next state from the POLAR runtime priority queue."""
        while self._heap_polar_native:
            entry = heapq.heappop(self._heap_polar_native)
            state_id = entry.state
            if state_id in self._frontier:
                return self._pop_state_with_scheduler_event(
                    state_id,
                    decision_source="polar_native",
                    priority=entry.priority,
                    path_decision="polar-cegis-native",
                    reason="highest-priority POLAR native state selected",
                )
        return None

    def _pop_first_live_state(self) -> VMState | None:
        """Pop any remaining live state if the priority queue unexpectedly goes stale."""
        for state_id in sorted(self._frontier.live_state_ids):
            state = self._pop_state_with_scheduler_event(
                state_id,
                decision_source="first_live_fallback",
                priority=None,
                path_decision="polar-cegis-native",
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
    ) -> VMState | None:
        """Pop one live state and emit the corresponding scheduler event."""
        observers = self._scheduler_event_observers
        frontier_size_before = len(self._frontier) if observers else 0
        estimated_resident_units = self._resident_units_by_state_id.get(state_id)
        features = self._frontier.runtime_features.get(state_id) if observers else None
        state = self._remove_state(state_id)
        if state is None:
            return None

        self._covered_pcs.update(state.visited_pcs)
        self._last_decisions["path"] = path_decision
        if observers:
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

    def _remove_state(self, state_id: int) -> VMState | None:
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
