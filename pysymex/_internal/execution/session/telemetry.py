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

"""Execution-session telemetry recording methods.

This module owns session-level degradation labels, structured fallback event
recording, source-line resolution, and passive observer notification. The
session state record owns the mutable fields these methods update.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pysymex._internal.execution.session.events import (
    add_unique_observer,
    event_with_resolved_line,
    notify_observers,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.execution.detectors.telemetry import DetectorQueryEvent
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
    from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent

logger = get_logger(__name__)


class _SessionTelemetryState(Protocol):
    """Session fields required by telemetry recording methods."""

    pc_to_line: dict[int, int]
    degraded_passes: list[str]
    fallback_events: list[FallbackEvent]
    fallback_event_observers: list[Callable[[FallbackEvent], None]]
    detector_query_event_observers: list[Callable[[DetectorQueryEvent], None]]
    path_feasibility_event_observers: list[Callable[[PathFeasibilityEvent], None]]
    scheduler_event_observers: list[Callable[[SchedulerEvent], None]]

    def record_degraded_passes(self, degraded_passes: list[str]) -> None:
        """Add degraded-pass markers without duplicating existing entries."""


class SessionTelemetryMixin:
    """Mixin for execution-session degraded-pass and observer telemetry."""

    __slots__ = ()

    def record_degraded_passes(
        self: _SessionTelemetryState,
        degraded_passes: list[str],
    ) -> None:
        """Add degraded-pass markers without duplicating existing entries."""
        for degraded_pass in degraded_passes:
            if degraded_pass not in self.degraded_passes:
                self.degraded_passes.append(degraded_pass)

    def record_fallback_event(self: _SessionTelemetryState, event: FallbackEvent) -> None:
        """Record a structured fallback event and mirror its degraded label."""
        event = event_with_resolved_line(event, self.pc_to_line)
        self.fallback_events.append(event)
        self.record_degraded_passes([event.label])
        notify_observers(
            self.fallback_event_observers,
            event,
            failure_message="Fallback event observer failed",
            logger=logger,
        )

    def add_fallback_event_observer(
        self: _SessionTelemetryState,
        observer: Callable[[FallbackEvent], None],
    ) -> None:
        """Register a passive observer for structured fallback events."""
        add_unique_observer(self.fallback_event_observers, observer)

    def record_detector_query_event(
        self: _SessionTelemetryState,
        event: DetectorQueryEvent,
    ) -> None:
        """Notify passive observers about one detector feasibility-query outcome."""
        event = event_with_resolved_line(event, self.pc_to_line)
        notify_observers(
            self.detector_query_event_observers,
            event,
            failure_message="Detector query event observer failed",
            logger=logger,
        )

    def add_detector_query_event_observer(
        self: _SessionTelemetryState,
        observer: Callable[[DetectorQueryEvent], None],
    ) -> None:
        """Register a passive observer for detector feasibility-query telemetry."""
        add_unique_observer(self.detector_query_event_observers, observer)

    def record_path_feasibility_event(
        self: _SessionTelemetryState,
        event: PathFeasibilityEvent,
    ) -> None:
        """Notify passive observers about one path-feasibility policy outcome."""
        event = event_with_resolved_line(event, self.pc_to_line)
        notify_observers(
            self.path_feasibility_event_observers,
            event,
            failure_message="Path feasibility event observer failed",
            logger=logger,
        )

    def add_path_feasibility_event_observer(
        self: _SessionTelemetryState,
        observer: Callable[[PathFeasibilityEvent], None],
    ) -> None:
        """Register a passive observer for path-feasibility policy telemetry."""
        add_unique_observer(self.path_feasibility_event_observers, observer)

    def record_scheduler_event(
        self: _SessionTelemetryState,
        event: SchedulerEvent,
    ) -> None:
        """Notify passive observers about one worklist scheduling decision."""
        event = event_with_resolved_line(event, self.pc_to_line)
        notify_observers(
            self.scheduler_event_observers,
            event,
            failure_message="Scheduler event observer failed",
            logger=logger,
        )

    def add_scheduler_event_observer(
        self: _SessionTelemetryState,
        observer: Callable[[SchedulerEvent], None],
    ) -> None:
        """Register a passive observer for path-frontier scheduling telemetry."""
        add_unique_observer(self.scheduler_event_observers, observer)
