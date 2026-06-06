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

"""Plain text reporting formatter."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from pysymex.config import VERSION
from pysymex.reporting.formatters.base import Formatter

if TYPE_CHECKING:
    from pysymex.execution.results.result import ExecutionResult


class TextFormatter(Formatter):
    """Plain text formatter for human-readable diagnostic reports.

    Attributes:
        SEVERITY_ICONS: Mapping from issue kind to display label.
    """

    name = "text"
    extension = ".txt"
    SEVERITY_ICONS = {
        "DIVISION_BY_ZERO": "[CRITICAL]",
        "ASSERTION_ERROR": "[CRITICAL]",
        "NULL_DEREFERENCE": "[CRITICAL]",
        "INDEX_ERROR": "[HIGH]",
        "KEY_ERROR": "[HIGH]",
        "TYPE_ERROR": "[MEDIUM]",
        "ATTRIBUTE_ERROR": "[MEDIUM]",
        "UNREACHABLE": "[INFO]",
        "INVALID_ARGUMENT": "[INFO]",
    }

    def __init__(self, color: bool = True, verbose: bool = False) -> None:
        """Initialise the text formatter.

        Args:
            color: Include Unicode severity icons.
            verbose: Include extra detail.
        """
        self.color = color
        self.verbose = verbose

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a human-readable text report.

        Args:
            result: Execution result to render.

        Returns:
            Multi-line string with summary, stats, and issues.
        """
        lines: list[str] = []
        lines.append("")
        lines.append("══════════════════════════════════════════════════════════════════════")
        lines.append("  pysymex — formal verification report")
        lines.append("══════════════════════════════════════════════════════════════════════")
        lines.append("")
        lines.append(f"  File:      {result.source_file}")
        lines.append(f"  Function:  {result.function_name}()")
        lines.append(f"  Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        if result.degraded_passes:
            lines.append("[ANALYSIS DEGRADED]:")
            lines.append(f"  {', '.join(result.degraded_passes)}")
            lines.append("")
        if result.issues:
            lines.append("[ISSUES FOUND]:")
            lines.append("──────────────────────────────────────────────────────────────────────")
            lines.append("")
            for i, issue in enumerate(result.issues, 1):
                severity = self.SEVERITY_ICONS.get(issue.kind.name, "[UNKNOWN]")
                lines.append(f"  [{i}] {severity}")
                lines.append(
                    f"    {result.source_file}:{issue.line_number} in {result.function_name}()"
                )
                lines.append(f"    {issue.message}")
                counterexample = issue.get_counterexample()
                if counterexample:
                    lines.append("    Crash when:")
                    for name, value in sorted(counterexample.items()):
                        lines.append(f"        {name} = {value}")
                lines.append("")
        elif result.degraded_passes:
            lines.append("  No findings reported; analysis was degraded.")
            lines.append("")
        else:
            lines.append("  No issues found!")
            lines.append("")
        lines.append("══════════════════════════════════════════════════════════════════════")
        lines.append("  Summary")
        lines.append("══════════════════════════════════════════════════════════════════════")
        lines.append(f"  Paths explored:   {result.paths_explored}")
        lines.append(f"  Paths completed:  {result.paths_completed}")
        lines.append(f"  Instructions:     {len(result.coverage)}")
        lines.append(f"  Execution time:  {result.total_time_seconds:.3f}s")
        lines.append("")
        lines.append(f"  pysymex v{VERSION} | https://github.com/darkoss1/pysymex")
        lines.append("")
        return "\n".join(lines)

    def format_verify(self, result: Any) -> str:
        """Format a VerifiedExecutionResult."""
        lines = [f"\n  --- Verified Execution: {result.function_name} ---"]
        if getattr(result, "degraded_passes", []):
            lines.append(f"  Analysis degraded: {', '.join(result.degraded_passes)}")
        if result.termination_proof:
            status_obj = result.termination_proof.status
            status_name = getattr(status_obj, "name", None)
            status = status_name if isinstance(status_name, str) else str(status_obj)
            lines.append(f"  Termination: {status} - {result.termination_proof.message}")
        if result.arithmetic_issues:
            lines.append(f"  Arithmetic issues: {len(result.arithmetic_issues)}")
            for ai in result.arithmetic_issues:
                format_fn = getattr(ai, "format", None)
                if callable(format_fn):
                    lines.append(f"    - {str(format_fn()).strip()}")
                else:
                    lines.append(f"    - {ai}")
        if result.contract_issues:
            for ci in result.contract_issues:
                format_fn = getattr(ci, "format", None)
                if callable(format_fn):
                    lines.append(f"    - {str(format_fn()).strip()}")
                else:
                    lines.append(f"    - {ci}")
        lines.append(
            f"  Paths: {result.paths_explored} explored, {result.paths_completed} completed"
        )
        return "\n".join(lines)


__all__ = ["TextFormatter"]
