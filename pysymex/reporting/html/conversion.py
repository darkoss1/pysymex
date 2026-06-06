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

"""Conversion and persistence helpers for HTML analysis reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pysymex.config import is_object_dict, is_object_list
from pysymex.reporting.html.models import AnalysisReport, IssueReport
from pysymex.reporting.html.rendering import generate_html_report
from pysymex.resources.models import ResourceSnapshot


def optional_int(value: object) -> int | None:
    """Return integer values, otherwise ``None``."""
    if isinstance(value, int):
        return value
    return None


def optional_input_dict(value: object) -> dict[str, object] | None:
    """Normalize optional triggering-input payloads."""
    if not is_object_dict(value):
        return None
    normalized: dict[str, object] = {}
    for key_obj, value_obj in value.items():
        normalized[str(key_obj)] = value_obj
    return normalized


def save_html_report(report: AnalysisReport, output_path: Path) -> None:
    """Save HTML report to file."""
    html_content = generate_html_report(report)
    output_path.write_text(html_content, encoding="utf-8")


def create_report_from_result(
    result: object,
    file_path: str,
    function_name: str,
    duration: float,
) -> AnalysisReport:
    """Create an AnalysisReport from an analysis result."""
    issues: list[IssueReport] = []
    raw_issues = getattr(result, "issues", None)
    if is_object_list(raw_issues):
        for issue in raw_issues:
            issue_obj: object = issue
            severity: str = "critical"
            raw_severity = getattr(issue_obj, "severity", None)
            if raw_severity is not None:
                severity = str(raw_severity)
            elif "warning" in str(type(issue_obj)).lower():
                severity = "warning"

            issue_type = str(getattr(issue_obj, "type", type(issue_obj).__name__))
            message = str(getattr(issue_obj, "message", issue_obj))
            line_number = optional_int(getattr(issue_obj, "line_number", None))
            triggering_input = optional_input_dict(getattr(issue_obj, "triggering_input", None))

            issues.append(
                IssueReport(
                    severity=severity,
                    issue_type=issue_type,
                    message=message,
                    file_path=file_path,
                    line_number=line_number,
                    function_name=function_name,
                    triggering_input=triggering_input,
                )
            )
    resources = None
    paths_explored = getattr(result, "paths_explored", 0)
    raw_error = getattr(result, "error", None)
    raw_degraded_passes = getattr(result, "degraded_passes", [])
    degraded_passes = (
        [str(degraded_pass) for degraded_pass in raw_degraded_passes]
        if is_object_list(raw_degraded_passes)
        else []
    )
    error_message = str(raw_error) if raw_error else None
    if error_message is None and degraded_passes:
        error_message = f"Analysis degraded: {', '.join(degraded_passes)}"
    if isinstance(paths_explored, int):
        resources = ResourceSnapshot(
            paths_explored=paths_explored,
            max_depth_reached=getattr(result, "max_depth", 0),
            elapsed_time=duration,
        )
    return AnalysisReport(
        title=f"Analysis of {function_name}()",
        timestamp=datetime.now().isoformat(),
        duration_seconds=duration,
        file_path=file_path,
        function_name=function_name,
        issues=issues,
        paths_explored=paths_explored if isinstance(paths_explored, int) else 0,
        paths_completed=getattr(result, "paths_completed", 0),
        resources=resources,
        success=not issues and error_message is None,
        partial=getattr(result, "partial", False) or bool(degraded_passes),
        error_message=error_message,
    )
