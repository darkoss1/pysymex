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

"""HTML formatter for scan results."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from pysymex._internal.analysis.records import normalize_trigger_input
from pysymex._internal.cli.formatters.base import CliFormatter, iter_verify_issue_records
from pysymex._internal.reporting.html.models import AnalysisReport, IssueReport
from pysymex._internal.reporting.html.rendering import generate_html_report

if TYPE_CHECKING:
    from collections.abc import Sequence


class HtmlFormatter(CliFormatter):
    """Outputs scan results as a standalone HTML report."""

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution scan results as an HTML report.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            duration (float): Execution duration in seconds.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
                Defaults to False.
            show_stats (bool): True to include performance statistics in the report.
                Defaults to False.

        Returns:
            str: Rendered HTML report string.

        """
        from pysymex._internal.limits.models import ResourceSnapshot

        all_issues: list[IssueReport] = []
        analysis_errors: list[str] = []
        degraded_analyses: list[str] = []
        paths_explored = 0
        max_depth = 0

        for scan_result in results:
            paths_explored += getattr(scan_result, "paths_explored", 0)
            max_depth = max(max_depth, getattr(scan_result, "max_depth_reached", 0))
            raw_error = getattr(scan_result, "error", None)
            if raw_error:
                analysis_errors.append(f"{getattr(scan_result, 'file_path', '')}: {raw_error}")
            raw_degraded_passes = list(getattr(scan_result, "degraded_passes", []))
            if raw_degraded_passes:
                degraded_analyses.append(
                    f"{getattr(scan_result, 'file_path', '')}: "
                    f"Analysis degraded: {', '.join(raw_degraded_passes)}",
                )
            if hasattr(scan_result, "issues"):
                for issue in scan_result.issues:
                    if isinstance(issue, dict):
                        issue_data = cast("dict[str, object]", issue)
                        ce = normalize_trigger_input(issue_data.get("counterexample"))
                        line_value = issue_data.get("line")
                        function_value = issue_data.get("function_name")
                        all_issues.append(
                            IssueReport(
                                severity="critical",
                                issue_type=str(issue_data.get("kind", "UNKNOWN")),
                                message=str(issue_data.get("message", "")),
                                file_path=str(getattr(scan_result, "file_path", "")),
                                line_number=line_value if isinstance(line_value, int) else None,
                                function_name=(
                                    function_value if isinstance(function_value, str) else None
                                ),
                                triggering_input=ce,
                            ),
                        )

        resources = ResourceSnapshot(
            paths_explored=paths_explored,
            max_depth_reached=max_depth,
            elapsed_time=duration,
        )

        diagnostics = [*analysis_errors, *degraded_analyses]
        report = AnalysisReport(
            title="symbolic execution report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=all_issues,
            paths_explored=paths_explored,
            resources=resources,
            success=total == 0 and not diagnostics,
            partial=bool(degraded_analyses),
            error_message="; ".join(diagnostics) if diagnostics else None,
        )
        return generate_html_report(report)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format formal verification results as an HTML report.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: Rendered HTML report string.

        """
        issues: list[IssueReport] = []
        paths_explored = 0
        degraded_analyses: list[str] = []
        for result in results:
            paths_explored += int(getattr(result, "paths_explored", 0))
            degraded_passes = list(getattr(result, "degraded_passes", []))
            if degraded_passes:
                degraded_analyses.append(
                    f"{getattr(result, 'function_name', 'unknown')}: "
                    f"Analysis degraded: {', '.join(degraded_passes)}",
                )
            for record in iter_verify_issue_records(result):
                issues.append(
                    IssueReport(
                        severity="error",
                        issue_type=record.issue_type,
                        message=record.message,
                        file_path=record.source_file,
                        line_number=record.line_number,
                        function_name=record.function_name,
                    ),
                )

        report = AnalysisReport(
            title="contract verification report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=issues,
            success=total == 0 and not degraded_analyses,
            partial=bool(degraded_analyses),
            error_message="; ".join(degraded_analyses) if degraded_analyses else None,
            paths_explored=paths_explored,
        )
        return generate_html_report(report)
