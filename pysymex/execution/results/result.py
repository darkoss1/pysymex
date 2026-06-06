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

from pysymex.analysis.detectors import Issue, IssueKind

__all__ = ["ExecutionResult"]


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
    suppressed_issue_offsets: frozenset[int] = field(default_factory=lambda: frozenset[int]())
    degraded_passes: list[str] = field(default_factory=list[str])

    def has_issues(self) -> bool:
        """Return whether any issues were emitted into this result."""
        return len(self.issues) > 0

    def get_issues_by_kind(self, kind: IssueKind) -> list[Issue]:
        """Return emitted issues whose kind equals ``kind``."""
        return [issue for issue in self.issues if issue.kind == kind]

    def format_summary(self) -> str:
        """Return a human-readable summary of recorded results and degradation."""
        lines = [
            "=== pysymex Execution Results ===",
            f"Function: {self.function_name}",
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
        from pysymex.execution.results.serialization import execution_result_to_dict

        return execution_result_to_dict(self)

    def to_sarif(self, output_path: str | None = None) -> dict[str, object]:
        """Return issue data as a SARIF v2.1.0 log and optionally write it.

        Notes:
            This compatibility method preserves the historic execution-result
            SARIF shape. General SARIF report generation lives under
            :mod:`pysymex.reporting.sarif`, which depends on runtime data rather
            than being imported from this execution layer.
        """
        from pysymex.execution.results.sarif import execution_result_to_sarif

        return execution_result_to_sarif(self, output_path)
