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

"""Passive scheduler telemetry records.

This module owns bounded diagnostics emitted by path-frontier scheduling.
Scheduler events are observational only: they do not participate in queue
ordering, pruning, solver decisions, detector publication, or result filtering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable

SchedulerAction = Literal["enqueue", "select"]
"""Closed set of scheduler actions exposed in trace output."""

SchedulerDecisionSource = Literal[
    "polar_native",
    "cegis_execute",
    "first_live_fallback",
]
"""Closed set of scheduler decision sources exposed in trace output."""


@dataclass(frozen=True, slots=True)
class SchedulerEvent:
    """Bounded diagnostic record for one frontier enqueue or selection."""

    action: SchedulerAction
    decision_source: SchedulerDecisionSource
    queue_state_id: int | None
    path_id: int
    pc: int | None
    line_number: int | None
    depth: int
    pending_constraint_count: int
    path_constraints_count: int
    frontier_size_before: int
    frontier_size_after: int
    branch_degree: int | None
    priority: float | None
    detector_obligation_count: int
    estimated_resident_units: int
    unsupported_live_count: int
    havoc_live_count: int
    reason: str = ""


@runtime_checkable
class SchedulerEventSource(Protocol):
    """Path manager capability for passive scheduler event observers."""

    def add_scheduler_event_observer(
        self,
        observer: Callable[[SchedulerEvent], None],
    ) -> None:
        """Register an observer for scheduler telemetry."""
        ...
