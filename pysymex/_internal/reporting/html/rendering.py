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

"""HTML report rendering helpers."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from pysymex._internal.reporting.html.template import HTML_TEMPLATE

if TYPE_CHECKING:
    from pysymex._internal.limits.models import ResourceSnapshot
    from pysymex._internal.reporting.html.models import AnalysisReport, IssueReport


def _issue_severity_class(severity: str) -> str:
    """Map issue severity strings to report CSS severity tiers."""
    normalized = severity.lower()
    if normalized in {"critical", "high", "error"}:
        return "critical"
    if normalized in {"warning", "medium", "warn"}:
        return "warning"
    if normalized in {"info", "low"}:
        return "info"
    return "critical"


def _issue_title_block(issue: IssueReport, severity_class: str) -> str:
    location = ""
    if issue.file_path:
        location = html.escape(issue.file_path)
        if issue.line_number is not None:
            location += f":{issue.line_number}"
    rank = html.escape(issue.severity.lower())
    return f"""
            <div class="issue__title">
                <div class="issue__heading">
                    <span class="issue__rank issue__rank--{severity_class}">{rank}</span>
                    <span class="issue__kind">{html.escape(issue.issue_type)}</span>
                </div>
                <span class="issue__loc">{location}</span>
            </div>
            <div class="issue__msg">{html.escape(issue.message)}</div>"""


def format_issue_html(issue: IssueReport, *, open_by_default: bool = False) -> str:
    """Render a single issue as a diagnostic row fragment."""
    severity_class = _issue_severity_class(issue.severity)
    title_block = _issue_title_block(issue, severity_class)
    if issue.triggering_input:
        inputs = ", ".join(
            f"<code>{html.escape(k)} = {html.escape(repr(v))}</code>"
            for k, v in issue.triggering_input.items()
        )
        open_attr = " open" if open_by_default else ""
        return f"""
        <details class="issue issue--{severity_class}"{open_attr}>
            <summary>{title_block}
            </summary>
            <div class="issue__detail">
                <div class="input-block">
                    <strong>Triggering input</strong>
                    {inputs}
                </div>
            </div>
        </details>"""
    return f"""
        <div class="issue issue--{severity_class} issue__static">{title_block}
        </div>"""


def format_issues_section(issues: list[IssueReport], error_message: str | None = None) -> str:
    """Render the full issues section as HTML."""
    if not issues and error_message:
        return """
            <div class="empty-state empty-state--error">
                <h3>No findings reported</h3>
                <p>Analysis did not complete successfully.</p>
            </div>
        """
    if not issues:
        return """
            <div class="empty-state empty-state--ok">
                <h3>No issues found</h3>
                <p>All explored paths completed without detecting any problems.</p>
            </div>
        """
    return "\n".join(
        format_issue_html(issue, open_by_default=(index == 0)) for index, issue in enumerate(issues)
    )


def format_error_html(error_message: str | None) -> str:
    """Render an escaped analysis-error diagnostic banner."""
    if error_message is None:
        return ""
    return (
        '<div class="analysis-error"><strong>Analysis error:</strong> '
        f"{html.escape(error_message)}</div>"
    )


def format_resources_html(resources: ResourceSnapshot | None) -> str:
    """Render resource-usage metrics as an HTML table."""
    if resources is None:
        return '<p class="resource-empty">No resource data available.</p>'
    rows = [
        ("Paths explored", str(resources.paths_explored)),
        ("Max depth reached", str(resources.max_depth_reached)),
        ("Iterations", f"{resources.iterations:,}"),
        ("Elapsed time", f"{resources.elapsed_time:.2f} s"),
        ("Solver calls", str(resources.solver_calls)),
        ("Cache hits", str(resources.cache_hits)),
    ]
    body = "\n".join(
        f"            <tr><th>{html.escape(label)}</th><td>{html.escape(value)}</td></tr>"
        for label, value in rows
    )
    return f"""
        <table class="metrics">
            <tbody>
{body}
            </tbody>
        </table>"""


def generate_html_report(report: AnalysisReport) -> str:
    """Generate a standalone HTML report."""
    if report.error_message:
        status = "Error"
        status_value_class = "summary__value--danger"
    elif report.partial:
        status = "Partial"
        status_value_class = "summary__value--warn"
    elif report.success:
        status = "Complete"
        status_value_class = "summary__value--ok"
    else:
        status = "Failed"
        status_value_class = "summary__value--danger"
    issue_count = len(report.issues)
    issue_count_class = "summary__value--danger" if issue_count > 0 else "summary__value--neutral"
    max_depth = report.resources.max_depth_reached if report.resources else 0
    return HTML_TEMPLATE.format(
        title=html.escape(report.title),
        file_path=html.escape(report.file_path),
        function_name=html.escape(report.function_name),
        timestamp=html.escape(report.timestamp),
        duration=report.duration_seconds,
        issue_count=issue_count,
        issue_count_class=issue_count_class,
        paths_explored=report.paths_explored,
        max_depth=max_depth,
        status=status,
        status_value_class=status_value_class,
        error_html=format_error_html(report.error_message),
        issues_html=format_issues_section(report.issues, report.error_message),
        resources_html=format_resources_html(report.resources),
        version=html.escape(report.version),
    )
