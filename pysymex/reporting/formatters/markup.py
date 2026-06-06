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

"""HTML and Markdown reporting formatters."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from pysymex.reporting.formatters.base import Formatter

if TYPE_CHECKING:
    from pysymex.execution.results.result import ExecutionResult


class HTMLFormatter(Formatter):
    """HTML formatter producing a self-contained report page."""

    name = "html"
    extension = ".html"

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a standalone HTML document.

        Args:
            result: Execution result to render.

        Returns:
            Complete HTML string.
        """
        from pysymex.reporting.html.conversion import create_report_from_result
        from pysymex.reporting.html.rendering import generate_html_report

        report = create_report_from_result(
            result,
            file_path=getattr(result, "source_file", "unknown"),
            function_name=getattr(result, "function_name", "unknown"),
            duration=getattr(result, "total_time_seconds", 0.0),
        )
        return generate_html_report(report)


class MarkdownFormatter(Formatter):
    """Markdown formatter for documentation-friendly output."""

    name = "markdown"
    extension = ".md"

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a Markdown document.

        Args:
            result: Execution result to render.

        Returns:
            Markdown string with tables and headings.
        """
        lines: list[str] = [
            "# pysymex - symbolic execution report",
            "",
            f"**Function:** `{result.function_name}`  ",
            f"**Source:** `{result.source_file}`  ",
            f"**Generated:** {datetime.now().isoformat()}",
            "",
            "## Statistics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Paths Explored | {result.paths_explored} |",
            f"| Paths Completed | {result.paths_completed} |",
            f"| Paths Pruned | {result.paths_pruned} |",
            f"| Coverage | {len(result.coverage)} instructions |",
            f"| Execution Time | {result.total_time_seconds:.3f}s |",
            "",
        ]
        if result.degraded_passes:
            lines.extend(
                [
                    "## Analysis Degraded",
                    "",
                    "The analysis completed with reduced precision:",
                    "",
                    *[f"- `{degraded_pass}`" for degraded_pass in result.degraded_passes],
                    "",
                ]
            )
        if result.issues:
            lines.append(f"## Issues Found ({len(result.issues)})")
            lines.append("")
            for i, issue in enumerate(result.issues, 1):
                lines.append(f"### {i}. {issue.kind.name.replace('_', ' ')}")
                lines.append("")
                lines.append(f"> {issue.message}")
                lines.append("")
                if issue.line_number:
                    lines.append(f"**Line:** {issue.line_number}  ")
                counterexample = issue.get_counterexample()
                if counterexample:
                    lines.append("")
                    lines.append("**Counterexample:**")
                    lines.append("```python")
                    for name, value in sorted(counterexample.items()):
                        lines.append(f"{name} = {value}")
                    lines.append("```")
                lines.append("")
        elif result.degraded_passes:
            lines.append("## No Findings Reported")
            lines.append("")
            lines.append("Analysis was degraded; this is not a verified clean result.")
        else:
            lines.append("## [OK] No Issues Found")
            lines.append("")
            lines.append("The symbolic execution did not detect any potential issues.")
        return "\n".join(lines)


__all__ = ["HTMLFormatter", "MarkdownFormatter"]
