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

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state.branches import BranchRecord
from pysymex.core.solver.constraints.hashing import ConstraintHasher
from pysymex.core.state.record import VMState
from pysymex.execution.detectors import (
    DeferredDetectorIssue,
    DetectorQueryCacheEntry,
    DetectorQueryEvent,
)
from pysymex.execution.fallback.types import FallbackEvent
from pysymex.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex.execution.scheduling.telemetry import SchedulerEvent
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.analysis.static.loops import LoopDetector, LoopWidening
    from pysymex.execution.strategies.manager.types import PathManager

__all__ = ["ExecutionSession"]

logger = get_logger(__name__)


def _phase_timers() -> dict[str, float]:
    """Return the fixed phase-timer schema used in execution results."""
    return {
        "execute_step": 0.0,
        "process_execution_result": 0.0,
        "path_feasibility": 0.0,
    }


def _phase_counts() -> dict[str, int]:
    """Return the fixed phase-count schema used in execution diagnostics."""
    return {
        "execute_step": 0,
        "process_execution_result": 0,
        "path_feasibility": 0,
    }


def _instructions() -> list[dis.Instruction]:
    return []


def _pc_to_line() -> dict[int, int]:
    return {}


def _issues() -> list[Issue]:
    return []


def _coverage() -> set[int]:
    return set()


def _visited_states() -> set[tuple[int, ...]]:
    return set()


def _prev_loop_states() -> dict[int, VMState]:
    return {}


def _loop_detectors() -> dict[tuple[int, ...], LoopDetector]:
    return {}


def _degraded_passes() -> list[str]:
    return []


def _fallback_events() -> list[FallbackEvent]:
    return []


def _fallback_event_observers() -> list[Callable[[FallbackEvent], None]]:
    return []


def _detector_query_event_observers() -> list[Callable[[DetectorQueryEvent], None]]:
    return []


def _path_feasibility_event_observers() -> list[Callable[[PathFeasibilityEvent], None]]:
    return []


def _scheduler_event_observers() -> list[Callable[[SchedulerEvent], None]]:
    return []


def _snapshot_mapping() -> dict[str, object]:
    return {}


def _branch_records() -> list[BranchRecord]:
    return []


def _snapshot_stack() -> list[object]:
    return []


def _detector_query_cache() -> OrderedDict[int, list[DetectorQueryCacheEntry]]:
    return OrderedDict()


def _deferred_detector_issues() -> list[DeferredDetectorIssue]:
    return []


def _reported_detector_sites() -> set[tuple[int, int, IssueKind]]:
    return set()


def _suppressed_detector_offsets() -> set[int]:
    return set()


@dataclass(slots=True)
class ExecutionSession:
    """Mutable state for one symbolic execution run.

    The session owns bytecode metadata, worklist state, result counters, issue
    publication state, detector query cache state, and terminal path snapshots.
    It deliberately does not own solver, dispatcher, detector registry, hooks,
    persistent result cache, resource tracker, or state merger objects.
    """

    instructions: list[dis.Instruction] = field(default_factory=_instructions)
    pc_to_line: dict[int, int] = field(default_factory=_pc_to_line)
    worklist: PathManager[VMState] | None = None
    issues: list[Issue] = field(default_factory=_issues)
    coverage: set[int] = field(default_factory=_coverage)
    visited_states: set[tuple[int, ...]] = field(default_factory=_visited_states)
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    iterations: int = 0
    loop_detector: LoopDetector | None = None
    loop_detectors: dict[tuple[int, ...], LoopDetector] = field(default_factory=_loop_detectors)
    loop_widening: LoopWidening | None = None
    prev_loop_states: dict[int, VMState] = field(default_factory=_prev_loop_states)
    degraded_passes: list[str] = field(default_factory=_degraded_passes)
    fallback_events: list[FallbackEvent] = field(default_factory=_fallback_events)
    fallback_event_observers: list[Callable[[FallbackEvent], None]] = field(
        default_factory=_fallback_event_observers
    )
    detector_query_event_observers: list[Callable[[DetectorQueryEvent], None]] = field(
        default_factory=_detector_query_event_observers
    )
    path_feasibility_event_observers: list[Callable[[PathFeasibilityEvent], None]] = field(
        default_factory=_path_feasibility_event_observers
    )
    scheduler_event_observers: list[Callable[[SchedulerEvent], None]] = field(
        default_factory=_scheduler_event_observers
    )
    phase_timers_seconds: dict[str, float] = field(default_factory=_phase_timers)
    phase_counts: dict[str, int] = field(default_factory=_phase_counts)
    last_globals: dict[str, object] = field(default_factory=_snapshot_mapping)
    last_locals: dict[str, object] = field(default_factory=_snapshot_mapping)
    last_branches: list[BranchRecord] = field(default_factory=_branch_records)
    last_stack: list[object] = field(default_factory=_snapshot_stack)
    last_exception: object | None = None
    detector_constraint_hasher: ConstraintHasher = field(default_factory=ConstraintHasher)
    detector_query_cache: OrderedDict[int, list[DetectorQueryCacheEntry]] = field(
        default_factory=_detector_query_cache
    )
    detector_query_cache_hits: int = 0
    detector_query_cache_misses: int = 0
    deferred_detector_issues: list[DeferredDetectorIssue] = field(
        default_factory=_deferred_detector_issues
    )
    reported_detector_sites: set[tuple[int, int, IssueKind]] = field(
        default_factory=_reported_detector_sites
    )
    suppressed_detector_offsets: set[int] = field(default_factory=_suppressed_detector_offsets)

    def reset_phase_stats(self) -> None:
        """Reset fixed-schema execution phase timing and count data."""
        self.phase_timers_seconds = _phase_timers()
        self.phase_counts = _phase_counts()

    def record_degraded_passes(self, degraded_passes: list[str]) -> None:
        """Add degraded-pass markers without duplicating existing entries."""
        for degraded_pass in degraded_passes:
            if degraded_pass not in self.degraded_passes:
                self.degraded_passes.append(degraded_pass)

    def record_fallback_event(self, event: FallbackEvent) -> None:
        """Record a structured fallback event and preserve degraded-label compatibility."""
        event = self._fallback_event_with_resolved_line(event)
        self.fallback_events.append(event)
        self.record_degraded_passes([event.label])
        for observer in self.fallback_event_observers:
            try:
                observer(event)
            except Exception:
                logger.debug("Fallback event observer failed", exc_info=True)

    def add_fallback_event_observer(self, observer: Callable[[FallbackEvent], None]) -> None:
        """Register a passive observer for structured fallback events."""
        if observer not in self.fallback_event_observers:
            self.fallback_event_observers.append(observer)

    def record_detector_query_event(self, event: DetectorQueryEvent) -> None:
        """Notify passive observers about one detector feasibility-query outcome."""
        event = self._detector_query_event_with_resolved_line(event)
        for observer in self.detector_query_event_observers:
            try:
                observer(event)
            except Exception:
                logger.debug("Detector query event observer failed", exc_info=True)

    def add_detector_query_event_observer(
        self,
        observer: Callable[[DetectorQueryEvent], None],
    ) -> None:
        """Register a passive observer for detector feasibility-query telemetry."""
        if observer not in self.detector_query_event_observers:
            self.detector_query_event_observers.append(observer)

    def record_path_feasibility_event(self, event: PathFeasibilityEvent) -> None:
        """Notify passive observers about one path-feasibility policy outcome."""
        event = self._path_feasibility_event_with_resolved_line(event)
        for observer in self.path_feasibility_event_observers:
            try:
                observer(event)
            except Exception:
                logger.debug("Path feasibility event observer failed", exc_info=True)

    def add_path_feasibility_event_observer(
        self,
        observer: Callable[[PathFeasibilityEvent], None],
    ) -> None:
        """Register a passive observer for path-feasibility policy telemetry."""
        if observer not in self.path_feasibility_event_observers:
            self.path_feasibility_event_observers.append(observer)

    def record_scheduler_event(self, event: SchedulerEvent) -> None:
        """Notify passive observers about one worklist scheduling decision."""
        event = self._scheduler_event_with_resolved_line(event)
        for observer in self.scheduler_event_observers:
            try:
                observer(event)
            except Exception:
                logger.debug("Scheduler event observer failed", exc_info=True)

    def add_scheduler_event_observer(
        self,
        observer: Callable[[SchedulerEvent], None],
    ) -> None:
        """Register a passive observer for path-frontier scheduling telemetry."""
        if observer not in self.scheduler_event_observers:
            self.scheduler_event_observers.append(observer)

    def _fallback_event_with_resolved_line(self, event: FallbackEvent) -> FallbackEvent:
        """Attach the source line for a fallback event when the session can resolve it."""
        if event.line_number is not None or event.pc is None:
            return event
        line_number = self.pc_to_line.get(event.pc)
        if line_number is None:
            return event
        return replace(event, line_number=line_number)

    def _detector_query_event_with_resolved_line(
        self,
        event: DetectorQueryEvent,
    ) -> DetectorQueryEvent:
        """Attach the source line for detector query telemetry when possible."""
        if event.line_number is not None or event.pc is None:
            return event
        line_number = self.pc_to_line.get(event.pc)
        if line_number is None:
            return event
        return replace(event, line_number=line_number)

    def _path_feasibility_event_with_resolved_line(
        self,
        event: PathFeasibilityEvent,
    ) -> PathFeasibilityEvent:
        """Attach the source line for path feasibility telemetry when possible."""
        if event.line_number is not None or event.pc is None:
            return event
        line_number = self.pc_to_line.get(event.pc)
        if line_number is None:
            return event
        return replace(event, line_number=line_number)

    def _scheduler_event_with_resolved_line(self, event: SchedulerEvent) -> SchedulerEvent:
        """Attach the source line for scheduler telemetry when possible."""
        if event.line_number is not None or event.pc is None:
            return event
        line_number = self.pc_to_line.get(event.pc)
        if line_number is None:
            return event
        return replace(event, line_number=line_number)

    def reset_last_execution_snapshots(self) -> None:
        """Reset terminal-path snapshots used in ``ExecutionResult``."""
        self.last_globals = {}
        self.last_locals = {}
        self.last_branches = []
        self.last_stack = []
        self.last_exception = None

    def reset_for_run(self, infrastructure_degraded_passes: list[str]) -> None:
        """Prepare this session for a new code object.

        Args:
            infrastructure_degraded_passes: Pre-existing infrastructure
                degradation labels to seed into the new run.
        """
        self.instructions = []
        self.pc_to_line = {}
        self.worklist = None
        self.issues = []
        self.coverage = set()
        self.visited_states = set()
        self.paths_explored = 1
        self.paths_completed = 0
        self.paths_pruned = 0
        self.iterations = 0
        self.loop_detector = None
        self.loop_detectors = {}
        self.loop_widening = None
        self.prev_loop_states = {}
        self.degraded_passes = list(infrastructure_degraded_passes)
        self.fallback_events = []
        self.reset_phase_stats()
        self.reset_last_execution_snapshots()
        self.detector_query_cache.clear()
        self.detector_constraint_hasher.clear()
        self.detector_query_cache_hits = 0
        self.detector_query_cache_misses = 0
        self.deferred_detector_issues = []
        self.reported_detector_sites = set()
        self.suppressed_detector_offsets = set()
