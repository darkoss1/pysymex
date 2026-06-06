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

"""Markdown formatter for scan results."""

from __future__ import annotations

from typing import Any, Sequence, cast

from pysymex.analysis.scan.records import normalize_trigger_input
from pysymex.cli.formatters.base import Formatter, verify_result_to_dict
from pysymex.config import VERSION


class MarkdownFormatter(Formatter):
    """Outputs scan results as a Markdown report."""

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution scan results as a Markdown report.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            duration (float): Execution duration in seconds.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
                Defaults to False.
            show_stats (bool): True to include performance statistics in the report.
                Defaults to False.

        Returns:
            str: Rendered Markdown report string.
        """
        analysis_errors = [
            f"{getattr(result, 'file_path', 'unknown')}: {getattr(result, 'error')}"
            for result in results
            if getattr(result, "error", None)
        ]
        degraded_analyses = [
            f"{getattr(result, 'file_path', 'unknown')}: {', '.join(degraded_passes)}"
            for result in results
            if (degraded_passes := list(getattr(result, "degraded_passes", [])))
        ]
        lines = [
            "# pysymex symbolic execution report",
            "",
            f"- **Files Scanned:** {len(results)}",
            f"- **Issues Found:** {total}",
            f"- **Analysis Errors:** {len(analysis_errors)}",
            f"- **Degraded Analyses:** {len(degraded_analyses)}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
            "## Issues",
            "",
        ]
        if total == 0 and not analysis_errors and not degraded_analyses:
            lines.append("No issues found.")
        elif total == 0 and analysis_errors and not degraded_analyses:
            lines.append("No findings reported; analysis did not complete successfully.")
        elif total == 0:
            lines.append("No findings reported; analysis was incomplete or degraded.")
        else:
            for scan_result in results:
                if not hasattr(scan_result, "issues") or not scan_result.issues:
                    continue
                file_path = getattr(scan_result, "file_path", "unknown")
                lines.append(f"## File: `{file_path}`")
                lines.append("")
                for issue in scan_result.issues:
                    if not isinstance(issue, dict):
                        continue
                    issue_dict = cast("dict[str, object]", issue)
                    kind = str(issue_dict.get("kind", "UNKNOWN"))
                    line = issue_dict.get("line", "?")
                    message = str(issue_dict.get("message", ""))
                    lines.append(f"### {kind}")
                    lines.append(f"- **Location:** `{file_path}:{line}`")
                    lines.append(f"- **Message:** {message}")
                    ce = normalize_trigger_input(issue_dict.get("counterexample"))
                    if ce is not None:
                        lines.append("- **Triggering Input:**")
                        lines.append("  ```python")
                        for k, v in sorted(ce.items()):
                            lines.append(f"  {k} = {repr(v)}")
                        lines.append("  ```")
                    lines.append("")
        if analysis_errors:
            lines.extend(["", "## Analysis Errors", ""])
            lines.extend(f"- {error}" for error in analysis_errors)
        if degraded_analyses:
            lines.extend(["", "## Degraded Analyses", ""])
            lines.extend(f"- {diagnostic}" for diagnostic in degraded_analyses)
        return "\n".join(lines)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format formal verification results as a Markdown report.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: Rendered Markdown report string.
        """
        degraded_results = [result for result in results if getattr(result, "degraded_passes", [])]
        lines = [
            "# pysymex contract verification report",
            "",
            f"- **Functions Verified:** {len(results)}",
            f"- **Findings:** {total}",
            f"- **Degraded Analyses:** {len(degraded_results)}",
            f"- **Duration:** {duration:.2f}s",
            f"- **Version:** {VERSION}",
            "",
        ]
        if not results:
            lines.append("No contracted functions were verified.")
            return "\n".join(lines)
        if total == 0 and not degraded_results:
            lines.append("All selected contracts verified.")
            return "\n".join(lines)
        if total == 0:
            lines.append("No findings reported; verification was degraded.")
            lines.append("")
            lines.append("## Degraded Analyses")
            lines.append("")
            for result in degraded_results:
                lines.append(
                    f"- `{getattr(result, 'function_name', 'unknown')}`: "
                    f"{', '.join(getattr(result, 'degraded_passes'))}"
                )
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")
        for result in results:
            data = verify_result_to_dict(result)
            if data["total_issues"] == 0:
                continue
            lines.append(f"### `{data['function_name']}`")
            lines.append("")
            lines.append(
                f"- **Paths:** {data['paths_explored']} explored, "
                f"{data['paths_completed']} completed"
            )
            for section, heading in (
                ("runtime_issues", "Runtime Issues"),
                ("contract_issues", "Contract Issues"),
                ("arithmetic_issues", "Arithmetic Issues"),
            ):
                issues = data[section]
                if isinstance(issues, list) and issues:
                    lines.append(f"- **{heading}:**")
                    lines.extend(f"  - {issue}" for issue in cast("list[object]", issues))
            lines.append("")
        return "\n".join(lines)
