"""HTML formatter for scan results."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence, cast

from pysymex.cli.formatters.base import Formatter, format_verify_issue
from pysymex.reporting.html import AnalysisReport, IssueReport, generate_html_report


class HtmlFormatter(Formatter):
    """Outputs scan results as a standalone HTML report."""

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        # Static reports don't have a dedicated HTML layout in html.py yet,
        # but we can adapt AnalysisReport.
        report = AnalysisReport(
            title="static analysis report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=[
                IssueReport(
                    severity=str(getattr(i, "severity", "warning")),
                    issue_type=str(getattr(i, "kind", "UNKNOWN")),
                    message=str(getattr(i, "message", "")),
                    file_path=str(getattr(i, "file", "")),
                    line_number=getattr(i, "line", None),
                )
                for i in issues
            ],
            success=total == 0,
        )
        return generate_html_report(report)

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        report = AnalysisReport(
            title="pipeline scan report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=[
                IssueReport(
                    severity=str(getattr(issue, "severity", "warning")),
                    issue_type=str(getattr(issue, "kind", "UNKNOWN")),
                    message=str(getattr(issue, "message", "")),
                    file_path=str(file_path),
                    line_number=getattr(issue, "line", None),
                )
                for file_path, issue in all_issues
            ],
            success=total == 0,
            paths_explored=len(results),
        )
        return generate_html_report(report)

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        from pysymex.resources import ResourceSnapshot

        all_issues: list[IssueReport] = []
        paths_explored = 0
        max_depth = 0

        for scan_result in results:
            paths_explored += getattr(scan_result, "paths_explored", 0)
            max_depth = max(max_depth, getattr(scan_result, "max_depth_reached", 0))
            if hasattr(scan_result, "issues"):
                for issue in scan_result.issues:
                    if isinstance(issue, dict):
                        issue_data = cast("dict[str, object]", issue)
                        ce = issue_data.get("counterexample")
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
                                triggering_input=(
                                    cast("dict[str, object]", ce) if isinstance(ce, dict) else None
                                ),
                            )
                        )

        resources = ResourceSnapshot(
            paths_explored=paths_explored,
            max_depth_reached=max_depth,
            elapsed_time=duration,
        )

        report = AnalysisReport(
            title="symbolic execution report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=all_issues,
            paths_explored=paths_explored,
            resources=resources,
            success=total == 0,
        )
        return generate_html_report(report)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        issues: list[IssueReport] = []
        paths_explored = 0
        for result in results:
            paths_explored += int(getattr(result, "paths_explored", 0))
            source_file = str(getattr(result, "source_file", ""))
            function_name = str(getattr(result, "function_name", ""))
            for issue in getattr(result, "issues", []):
                issues.append(
                    IssueReport(
                        severity="error",
                        issue_type=str(getattr(issue, "kind", "RUNTIME")),
                        message=format_verify_issue(issue),
                        file_path=source_file,
                        line_number=getattr(issue, "line_number", None),
                        function_name=function_name,
                    )
                )
            for issue in getattr(result, "contract_issues", []):
                issues.append(
                    IssueReport(
                        severity="error",
                        issue_type=str(getattr(issue, "kind", "CONTRACT")),
                        message=format_verify_issue(issue),
                        file_path=source_file,
                        line_number=getattr(issue, "line_number", None),
                        function_name=function_name,
                    )
                )
            for issue in getattr(result, "arithmetic_issues", []):
                issues.append(
                    IssueReport(
                        severity="error",
                        issue_type=str(getattr(issue, "kind", "ARITHMETIC")),
                        message=format_verify_issue(issue),
                        file_path=source_file,
                        line_number=getattr(issue, "line_number", None),
                        function_name=function_name,
                    )
                )

        report = AnalysisReport(
            title="contract verification report",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            issues=issues,
            success=total == 0,
            paths_explored=paths_explored,
        )
        return generate_html_report(report)
