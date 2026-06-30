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

"""Execution-session reset lifecycle methods."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pysymex._internal.execution.session.state.defaults.phase import (
    default_phase_counts,
    default_phase_timers,
)

if TYPE_CHECKING:
    import dis
    from collections import OrderedDict

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.outcome import IssueKind
    from pysymex._internal.core.solver.constraints.hashing import ConstraintHasher
    from pysymex._internal.core.state.branches import BranchRecord
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.detectors.records import (
        DeferredDetectorIssue,
        DetectorQueryCacheEntry,
    )
    from pysymex._internal.execution.fallback.types import FallbackEvent
    from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
    from pysymex._internal.execution.scheduling.loops.widening import LoopWidening
    from pysymex._internal.execution.strategies.manager.types import PathManager


class _SessionLifecycleState(Protocol):
    """Session fields required by reset lifecycle methods."""

    instructions: list[dis.Instruction]
    pc_to_line: dict[int, int]
    worklist: PathManager[VMState] | None
    issues: list[Issue]
    coverage: set[int]
    visited_states: set[tuple[int, ...]]
    paths_explored: int
    paths_completed: int
    paths_pruned: int
    iterations: int
    loop_detector: LoopDetector | None
    loop_detectors: dict[tuple[int, ...], LoopDetector]
    loop_widening: LoopWidening | None
    prev_loop_states: dict[int, VMState]
    degraded_passes: list[str]
    fallback_events: list[FallbackEvent]
    phase_timers_seconds: dict[str, float]
    phase_counts: dict[str, int]
    last_globals: dict[str, object]
    last_locals: dict[str, object]
    last_branches: list[BranchRecord]
    last_stack: list[object]
    last_exception: object | None
    detector_constraint_hasher: ConstraintHasher
    detector_query_cache: OrderedDict[int, list[DetectorQueryCacheEntry]]
    detector_query_cache_hits: int
    detector_query_cache_misses: int
    deferred_detector_issues: list[DeferredDetectorIssue]
    reported_detector_sites: set[tuple[int, int, IssueKind]]
    suppressed_detector_offsets: set[int]

    def reset_phase_stats(self) -> None:
        """Reset fixed-schema execution phase timing and count data."""

    def reset_last_execution_snapshots(self) -> None:
        """Reset terminal-path snapshots used in execution results."""


class SessionLifecycleMixin:
    """Mixin for execution-session per-run reset lifecycle."""

    __slots__ = ()

    def reset_phase_stats(self: _SessionLifecycleState) -> None:
        """Reset fixed-schema execution phase timing and count data."""
        self.phase_timers_seconds = default_phase_timers()
        self.phase_counts = default_phase_counts()

    def reset_last_execution_snapshots(self: _SessionLifecycleState) -> None:
        """Reset terminal-path snapshots used in ``ExecutionResult``."""
        self.last_globals = {}
        self.last_locals = {}
        self.last_branches = []
        self.last_stack = []
        self.last_exception = None

    def reset_for_run(
        self: _SessionLifecycleState,
        infrastructure_degraded_passes: list[str],
    ) -> None:
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
