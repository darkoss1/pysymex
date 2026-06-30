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

"""Scheduler trace event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.schemas.events import SchedulerTraceEvent

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pysymex._internal.config.tracing.settings import TracerConfig
    from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent


class TracerSchedulerMixin:
    """Structured trace emission for path-frontier scheduling decisions."""

    if TYPE_CHECKING:
        config: TracerConfig

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number."""
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer."""
            ...

    def on_scheduler_event(self, event: SchedulerEvent) -> None:
        """Emit structured telemetry for one scheduler enqueue or selection."""
        if not self.config.enabled:
            return

        trace_event = SchedulerTraceEvent(
            seq=self._next_seq(),
            action=event.action,
            decision_source=event.decision_source,
            queue_state_id=event.queue_state_id,
            path_id=event.path_id,
            pc=event.pc,
            source_line=event.line_number,
            depth=event.depth,
            pending_constraint_count=event.pending_constraint_count,
            path_constraints_count=event.path_constraints_count,
            frontier_size_before=event.frontier_size_before,
            frontier_size_after=event.frontier_size_after,
            branch_degree=event.branch_degree,
            priority=event.priority,
            detector_obligation_count=event.detector_obligation_count,
            estimated_resident_units=event.estimated_resident_units,
            unsupported_live_count=event.unsupported_live_count,
            havoc_live_count=event.havoc_live_count,
            reason=event.reason,
        )
        self._write_event(trace_event, force_flush=False)
