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

"""JSON reporting formatter."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import VERSION
from pysymex._internal.reporting.formatters.base import Formatter

if TYPE_CHECKING:
    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.execution.results.result import ExecutionResult


class JSONFormatter(Formatter):
    """JSON formatter for machine-readable output.

    Attributes:
        indent: Number of spaces for JSON indentation.
        include_constraints: Whether to include raw Z3 constraints.

    """

    name = "json"
    extension = ".json"

    def __init__(self, indent: int = 2, include_constraints: bool = False) -> None:
        """Initialise the JSON formatter.

        Args:
            indent: JSON indentation level.
            include_constraints: Embed Z3 constraint strings.

        """
        self.indent = indent
        self.include_constraints = include_constraints

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a JSON document.

        Args:
            result: Execution result to serialise.

        Returns:
            Pretty-printed JSON string.

        """
        data = {
            "meta": {
                "tool": "pysymex",
                "version": VERSION,
                "timestamp": datetime.now().isoformat(),
            },
            "function": {
                "name": result.function_name,
                "source_file": result.source_file,
            },
            "statistics": {
                "paths_explored": result.paths_explored,
                "paths_completed": result.paths_completed,
                "paths_pruned": result.paths_pruned,
                "coverage_instructions": len(result.coverage),
                "execution_time_seconds": result.total_time_seconds,
            },
            "issues": [self._format_issue(issue) for issue in result.issues],
            "summary": {
                "total_issues": len(result.issues),
                "analysis_degraded": bool(result.degraded_passes),
                "degraded_passes": list(result.degraded_passes),
                "has_critical": any(
                    i.kind.name in ("DIVISION_BY_ZERO", "ASSERTION_ERROR") for i in result.issues
                ),
            },
            "environment": {
                "python_version": "3.x",
            },
        }
        return json.dumps(data, indent=self.indent, default=str)

    def _format_issue(self, issue: Issue) -> dict[str, object]:
        """Serialise a single *issue* to a JSON-friendly dict."""
        data: dict[str, object] = {
            "kind": issue.kind.name,
            "message": issue.message,
            "line_number": issue.line_number,
            "function_name": issue.function_name,
            "pc": issue.pc,
            "counterexample": issue.get_counterexample(),
        }
        if self.include_constraints:
            data["constraints"] = [str(c) for c in issue.constraints]
        return data
