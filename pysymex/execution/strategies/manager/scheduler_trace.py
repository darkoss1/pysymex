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

"""Scheduler trace emission helpers for POLAR path managers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from pysymex.execution.scheduling.telemetry import (
    SchedulerAction,
    SchedulerDecisionSource,
    SchedulerEvent,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.frontier.store import FrontierRuntimeFeatures

logger = get_logger(__name__)


class SchedulerTraceMixin:
    """Passive scheduler-event observer support."""

    _scheduler_event_observers: list[Callable[[SchedulerEvent], None]]

    def _init_scheduler_event_observers(self) -> None:
        """Initialize the passive scheduler observer list."""
        self._scheduler_event_observers = []

    def add_scheduler_event_observer(
        self,
        observer: Callable[[SchedulerEvent], None],
    ) -> None:
        """Register a passive observer for scheduler decisions."""
        if observer not in self._scheduler_event_observers:
            self._scheduler_event_observers.append(observer)

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
    ) -> None:
        """Emit bounded scheduler telemetry when tracing has installed observers."""
        if not self._scheduler_event_observers:
            return
        detector_count = len(state.deferred_detector_issues)
        unsupported_count = 0
        havoc_count = 0
        if features is not None:
            detector_count = features.detector_obligation_count
            unsupported_count = features.unsupported_live_count
            havoc_count = features.havoc_live_count
            estimated_resident_units = features.estimated_resident_units

        event = SchedulerEvent(
            action=action,
            decision_source=decision_source,
            queue_state_id=state_id,
            path_id=state.path_id,
            pc=state.pc,
            line_number=None,
            depth=state.depth,
            pending_constraint_count=state.pending_constraint_count,
            path_constraints_count=len(state.path_constraints),
            frontier_size_before=frontier_size_before,
            frontier_size_after=frontier_size_after,
            branch_degree=branch_degree,
            priority=priority,
            detector_obligation_count=detector_count,
            estimated_resident_units=estimated_resident_units,
            unsupported_live_count=unsupported_count,
            havoc_live_count=havoc_count,
            reason=reason,
        )
        for observer in self._scheduler_event_observers:
            try:
                observer(event)
            except Exception:
                logger.debug("Scheduler event observer failed", exc_info=True)


__all__ = ["SchedulerTraceMixin"]
