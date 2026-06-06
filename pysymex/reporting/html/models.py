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

"""HTML report data models."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.config import VERSION
from pysymex.resources.models import ResourceSnapshot


def new_issue_reports() -> list["IssueReport"]:
    """Create an empty typed issue-report list."""
    return []


@dataclass
class IssueReport:
    """Report for a single issue."""

    severity: str
    issue_type: str
    message: str
    file_path: str | None = None
    line_number: int | None = None
    function_name: str | None = None
    triggering_input: dict[str, object] | None = None
    constraint_info: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "severity": self.severity,
            "type": self.issue_type,
            "message": self.message,
            "file": self.file_path,
            "line": self.line_number,
            "function": self.function_name,
            "input": self.triggering_input,
            "constraint": self.constraint_info,
        }


@dataclass
class AnalysisReport:
    """Complete analysis report."""

    title: str
    timestamp: str
    duration_seconds: float
    version: str = VERSION
    file_path: str = ""
    function_name: str = ""
    issues: list[IssueReport] = field(default_factory=new_issue_reports)
    paths_explored: int = 0
    paths_completed: int = 0
    resources: ResourceSnapshot | None = None
    success: bool = True
    partial: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "timestamp": self.timestamp,
            "duration": self.duration_seconds,
            "version": self.version,
            "file": self.file_path,
            "function": self.function_name,
            "issues": [i.to_dict() for i in self.issues],
            "paths_explored": self.paths_explored,
            "paths_completed": self.paths_completed,
            "resources": self.resources.to_dict() if self.resources else None,
            "success": self.success,
            "partial": self.partial,
            "error": self.error_message,
        }
