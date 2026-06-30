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

"""Execution result data returned by symbolic execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import (
    AnalysisOutcome,
    IssueKind,
    OutcomeEvidence,
    OutcomePolicy,
)
from pysymex._internal.execution.fallback.types import FallbackKind, SoundnessTag

if TYPE_CHECKING:
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.limits.models import ResourceSnapshot


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Recorded outcome of a symbolic execution attempt.

    The result captures completed work, emitted issues, coverage, and
    degradation markers. It does not itself prove that every feasible path
    was explored or that an empty issue list establishes safety.
    """

    issues: list[Issue] = field(default_factory=list[Issue])
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    coverage: set[int] = field(default_factory=set[int])
    total_time_seconds: float = 0.0
    solver_time_seconds: float = 0.0
    avg_memory_mb: float = 0.0
    function_name: str = ""
    source_file: str = ""
    final_globals: dict[str, object] = field(default_factory=dict[str, object])
    final_locals: dict[str, object] = field(default_factory=dict[str, object])
    final_stack: list[object] = field(default_factory=list[object])
    final_exception: object | None = None
    branches: list[object] = field(default_factory=list[object])
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])
    suppressed_issue_offsets: frozenset[int] = field(default_factory=frozenset[int])
    degraded_passes: list[str] = field(default_factory=list[str])
    outcome_evidence: list[OutcomeEvidence] = field(default_factory=list[OutcomeEvidence])

    @property
    def outcome(self) -> AnalysisOutcome:
        """Return the top-level outcome classification of this execution."""
        return OutcomePolicy.classify(
            self.issues,
            self.degraded_passes,
            self.outcome_evidence,
        )[0]

    @property
    def outcome_subreason(self) -> str | None:
        """Return the detailed subreason for this execution's outcome classification."""
        return OutcomePolicy.classify(
            self.issues,
            self.degraded_passes,
            self.outcome_evidence,
        )[1]

    def has_issues(self) -> bool:
        """Return whether any issues were emitted into this result."""
        return len(self.issues) > 0

    def get_issues_by_kind(self, kind: IssueKind) -> list[Issue]:
        """Return emitted issues whose kind equals ``kind``."""
        return [issue for issue in self.issues if issue.kind == kind]

    @classmethod
    def from_session(
        cls,
        *,
        session: ExecutionSession,
        final_issues: list[Issue],
        resource_snapshot: ResourceSnapshot,
        solver_stats: dict[str, object],
        detector_query_stats: dict[str, object],
        state_merger_stats: dict[str, object],
        worklist_stats: dict[str, object],
        function_name: str,
        source_file: str,
        include_final_stack: bool,
        include_final_exception: bool,
    ) -> ExecutionResult:
        """Build a result from finalized execution session telemetry."""
        return cls(
            issues=final_issues,
            paths_explored=session.paths_explored,
            paths_completed=session.paths_completed,
            paths_pruned=session.paths_pruned,
            coverage=session.coverage,
            total_time_seconds=resource_snapshot.elapsed_time,
            solver_time_seconds=cast("float", solver_stats.get("solver_time_ms", 0.0)) / 1000.0,
            avg_memory_mb=resource_snapshot.avg_memory_mb,
            function_name=function_name,
            source_file=source_file,
            final_globals=session.last_globals,
            final_locals=session.last_locals,
            final_stack=session.last_stack if include_final_stack else [],
            final_exception=session.last_exception if include_final_exception else None,
            branches=list(session.last_branches),
            solver_stats={
                **solver_stats,
                "detector_queries": detector_query_stats,
                "state_merger": state_merger_stats,
                "worklist": _worklist_stats_with_fallbacks(session, worklist_stats),
            },
            suppressed_issue_offsets=frozenset(session.suppressed_detector_offsets),
            degraded_passes=session.degraded_passes,
            outcome_evidence=OutcomePolicy.evidence_from_fallback_events(session.fallback_events),
        )

    def format_summary(self) -> str:
        """Return a human-readable summary of recorded results and degradation."""
        outcome_str = self.outcome.name
        if self.outcome_subreason:
            outcome_str += f" ({self.outcome_subreason})"
        lines = [
            "=== pysymex Execution Results ===",
            f"Function: {self.function_name}",
            f"Outcome: {outcome_str}",
            f"Paths explored: {self.paths_explored}",
            f"Paths completed: {self.paths_completed}",
            f"Coverage: {len(self.coverage)} bytecode instructions",
            f"Total time: {self.total_time_seconds:.2f}s",
            f"Avg Memory: {self.avg_memory_mb:.2f} MB",
            "",
        ]
        if self.degraded_passes:
            lines.append(f"Analysis degraded: {', '.join(self.degraded_passes)}")
            lines.append("")
        if self.issues:
            lines.append(f"Issues found: {len(self.issues)}")
            for issue in self.issues:
                lines.append("")
                lines.append(issue.format())
        elif self.degraded_passes:
            lines.append("No findings reported; analysis was degraded.")
        else:
            lines.append("No issues found!")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """Return selected summary fields and issue payloads for serialization."""
        from pysymex._internal.execution.results.serialization import execution_result_to_dict

        return execution_result_to_dict(self)

def _worklist_stats_with_fallbacks(
    session: ExecutionSession,
    worklist_stats: dict[str, object],
) -> dict[str, object]:
    """Return worklist diagnostics extended with fallback visibility counters."""
    fallback_events = session.fallback_events
    fallback_kind_counts = {
        kind.value: sum(1 for event in fallback_events if event.kind is kind)
        for kind in FallbackKind
    }
    fallback_soundness_counts = {
        tag.value: sum(1 for event in fallback_events if event.soundness is tag)
        for tag in SoundnessTag
    }
    return {
        **worklist_stats,
        "degraded_pass_count": len(session.degraded_passes),
        "fallback_event_count": len(fallback_events),
        "fallback_kind_counts": fallback_kind_counts,
        "fallback_soundness_counts": fallback_soundness_counts,
    }
