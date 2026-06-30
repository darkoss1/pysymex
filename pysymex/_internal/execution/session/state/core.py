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

"""Per-run symbolic execution state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher
from pysymex._internal.execution.session.lifecycle import SessionLifecycleMixin
from pysymex._internal.execution.session.state.defaults.bytecode import (
    default_coverage,
    default_instructions,
    default_pc_to_line,
    default_visited_states,
)
from pysymex._internal.execution.session.state.defaults.detectors import (
    default_deferred_detector_issues,
    default_detector_query_cache,
    default_reported_detector_sites,
    default_suppressed_detector_offsets,
)
from pysymex._internal.execution.session.state.defaults.loops import (
    default_loop_detectors,
    default_prev_loop_states,
)
from pysymex._internal.execution.session.state.defaults.phase import (
    default_phase_counts,
    default_phase_timers,
)
from pysymex._internal.execution.session.state.defaults.results import (
    default_degraded_passes,
    default_issues,
)
from pysymex._internal.execution.session.state.defaults.snapshots import (
    default_branch_records,
    default_snapshot_mapping,
    default_snapshot_stack,
)
from pysymex._internal.execution.session.state.defaults.telemetry import (
    default_detector_query_event_observers,
    default_fallback_event_observers,
    default_fallback_events,
    default_path_feasibility_event_observers,
    default_scheduler_event_observers,
)
from pysymex._internal.execution.session.telemetry import SessionTelemetryMixin

if TYPE_CHECKING:
    import dis
    from collections import OrderedDict
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.outcome import IssueKind
    from pysymex._internal.core.state.branches import BranchRecord
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.detectors.records import (
        DeferredDetectorIssue,
        DetectorQueryCacheEntry,
    )
    from pysymex._internal.execution.detectors.telemetry import DetectorQueryEvent
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.execution.feasibility.telemetry import PathFeasibilityEvent
    from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
    from pysymex._internal.execution.scheduling.loops.widening import LoopWidening
    from pysymex._internal.execution.scheduling.telemetry import SchedulerEvent
    from pysymex._internal.execution.strategies.manager.types import PathManager


@dataclass(slots=True)
class ExecutionSession(SessionLifecycleMixin, SessionTelemetryMixin):
    """Mutable state for one symbolic execution run.

    The session owns bytecode metadata, worklist state, result counters, issue
    publication state, detector query cache state, and terminal path snapshots.
    It deliberately does not own solver, dispatcher, detector registry, hooks,
    persistent result cache, resource tracker, or state merger objects.
    """

    instructions: list[dis.Instruction] = field(default_factory=default_instructions)
    pc_to_line: dict[int, int] = field(default_factory=default_pc_to_line)
    worklist: PathManager[VMState] | None = None
    issues: list[Issue] = field(default_factory=default_issues)
    coverage: set[int] = field(default_factory=default_coverage)
    visited_states: set[tuple[int, ...]] = field(default_factory=default_visited_states)
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    iterations: int = 0
    loop_detector: LoopDetector | None = None
    loop_detectors: dict[tuple[int, ...], LoopDetector] = field(
        default_factory=default_loop_detectors,
    )
    loop_widening: LoopWidening | None = None
    prev_loop_states: dict[int, VMState] = field(default_factory=default_prev_loop_states)
    degraded_passes: list[str] = field(default_factory=default_degraded_passes)
    fallback_events: list[FallbackEvent] = field(default_factory=default_fallback_events)
    fallback_event_observers: list[Callable[[FallbackEvent], None]] = field(
        default_factory=default_fallback_event_observers,
    )
    detector_query_event_observers: list[Callable[[DetectorQueryEvent], None]] = field(
        default_factory=default_detector_query_event_observers,
    )
    path_feasibility_event_observers: list[Callable[[PathFeasibilityEvent], None]] = field(
        default_factory=default_path_feasibility_event_observers,
    )
    scheduler_event_observers: list[Callable[[SchedulerEvent], None]] = field(
        default_factory=default_scheduler_event_observers,
    )
    phase_timers_seconds: dict[str, float] = field(default_factory=default_phase_timers)
    phase_counts: dict[str, int] = field(default_factory=default_phase_counts)
    last_globals: dict[str, object] = field(default_factory=default_snapshot_mapping)
    last_locals: dict[str, object] = field(default_factory=default_snapshot_mapping)
    last_branches: list[BranchRecord] = field(default_factory=default_branch_records)
    last_stack: list[object] = field(default_factory=default_snapshot_stack)
    last_exception: object | None = None
    detector_constraint_hasher: ConstraintHasher = field(default_factory=ConstraintHasher)
    detector_query_cache: OrderedDict[int, list[DetectorQueryCacheEntry]] = field(
        default_factory=default_detector_query_cache,
    )
    detector_query_cache_hits: int = 0
    detector_query_cache_misses: int = 0
    deferred_detector_issues: list[DeferredDetectorIssue] = field(
        default_factory=default_deferred_detector_issues,
    )
    reported_detector_sites: set[tuple[int, int, IssueKind]] = field(
        default_factory=default_reported_detector_sites,
    )
    suppressed_detector_offsets: set[int] = field(
        default_factory=default_suppressed_detector_offsets,
    )
