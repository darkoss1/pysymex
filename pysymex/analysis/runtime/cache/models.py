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

"""Task and result models for parallel analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalysisTask:
    """A unit of work for parallel analysis with priority and dependency tracking.

    Higher ``priority`` values sort first (used as max-heap ordering in
    ``ParallelAnalyzer``).
    """

    task_id: str
    target: object
    priority: int = 0
    dependencies: list[str] = field(default_factory=list[str])

    def __lt__(self, other: AnalysisTask) -> bool:
        """Compare two AnalysisTasks by priority for sorting in priority queues.

        Args:
            other (AnalysisTask): The other task.

        Returns:
            bool: True if this task has higher priority than the other, False otherwise.
        """
        return self.priority > other.priority


@dataclass
class AnalysisResult:
    """Outcome of a single analysis task execution.

    Carries the analysis return value on success, or an error message
    string on failure, plus wall-clock duration.
    """

    task_id: str
    success: bool
    result: object = None
    error: str | None = None
    duration: float = 0.0


__all__ = ["AnalysisResult", "AnalysisTask"]
