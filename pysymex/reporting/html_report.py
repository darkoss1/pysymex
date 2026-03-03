"""HTML report generation for pysymex.
Generates standalone HTML reports with analysis results, visualizations,
and interactive features.
"""

from __future__ import annotations


import html

from dataclasses import dataclass, field

from datetime import datetime

from pathlib import Path

from typing import Any


from pysymex.resources import ResourceSnapshot


@dataclass
class IssueReport:
    """Report for a single issue."""

    severity: str

    issue_type: str

    message: str

    file_path: str | None = None

    line_number: int | None = None

    function_name: str | None = None

    triggering_input: dict[str, Any] | None = None

    constraint_info: str | None = None

    def to_dict(self) -> dict[str, Any]:
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

    version: str = "1.0.0"

    file_path: str = ""

    function_name: str = ""

    issues: list[IssueReport] = field(default_factory=list[IssueReport])

    paths_explored: int = 0

    paths_completed: int = 0

    resources: ResourceSnapshot | None = None

    success: bool = True

    partial: bool = False

    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
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


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - PySyMex Report</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eaeaea;
            --text-secondary: #a0a0a0;
            --accent: #e94560;
            --accent-success: #00d26a;
            --accent-warning: #ffc107;
            --accent-info: #17a2b8;
            --border: #2a2a4a;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }}
        h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo {{
            font-size: 2.5rem;
        }}
        .meta {{
            display: flex;
            gap: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            flex-wrap: wrap;
        }}
        .meta span {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-card.critical .value {{ color: var(--accent); }}
        .stat-card.warning .value {{ color: var(--accent-warning); }}
        .stat-card.success .value {{ color: var(--accent-success); }}
        .stat-card.info .value {{ color: var(--accent-info); }}
        section {{
            background: var(--bg-secondary);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }}
        h2 {{
            font-size: 1.3rem;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }}
        .issue {{
            background: var(--bg-primary);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 12px;
            border-left: 4px solid var(--accent);
        }}
        .issue.warning {{
            border-left-color: var(--accent-warning);
        }}
        .issue.info {{
            border-left-color: var(--accent-info);
        }}
        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .issue-type {{
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: var(--accent); }}
        .badge.warning {{ background: var(--accent-warning); color: #000; }}
        .badge.info {{ background: var(--accent-info); }}
        .issue-location {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        .issue-message {{
            margin-bottom: 10px;
        }}
        .input-example {{
            background: var(--bg-card);
            padding: 10px 15px;
            border-radius: 6px;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }}
        .input-example code {{
            color: var(--accent-success);
        }}
        .no-issues {{
            text-align: center;
            padding: 40px;
            color: var(--accent-success);
        }}
        .no-issues .icon {{
            font-size: 4rem;
            margin-bottom: 15px;
        }}
        .resources {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
        }}
        .resource-item {{
            background: var(--bg-primary);
            padding: 12px;
            border-radius: 6px;
            text-align: center;
        }}
        .resource-item .value {{
            font-size: 1.3rem;
            font-weight: bold;
            color: var(--accent-info);
        }}
        .resource-item .label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
            padding: 20px;
        }}
        .collapsible {{
            cursor: pointer;
        }}
        .collapsible:after {{
            content: ' ▼';
            font-size: 0.8rem;
        }}
        .collapsed:after {{
            content: ' ▶';
        }}
        .collapse-content {{
            display: none;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid var(--border);
        }}
        .collapse-content.show {{
            display: block;
        }}
        @media (max-width: 600px) {{
            .meta {{
                flex-direction: column;
                gap: 8px;
            }}
            h1 {{
                font-size: 1.5rem;
            }}
            .stat-card .value {{
                font-size: 2rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span class="logo">👁️</span> {title}</h1>
            <div class="meta">
                <span>📁 {file_path}</span>
                <span>⚡ {function_name}()</span>
                <span>🕐 {timestamp}</span>
                <span>⏱️ {duration:.2f}s</span>
            </div>
        </header>
        <div class="summary">
            <div class="stat-card {issues_class}">
                <div class="value">{issue_count}</div>
                <div class="label">Issues Found</div>
            </div>
            <div class="stat-card info">
                <div class="value">{paths_explored}</div>
                <div class="label">Paths Explored</div>
            </div>
            <div class="stat-card info">
                <div class="value">{max_depth}</div>
                <div class="label">Max Depth</div>
            </div>
            <div class="stat-card {status_class}">
                <div class="value">{status}</div>
                <div class="label">Status</div>
            </div>
        </div>
        <section>
            <h2>🔍 Issues</h2>
            {issues_html}
        </section>
        <section>
            <h2>📊 Resource Usage</h2>
            <div class="resources">
                {resources_html}
            </div>
        </section>
        <footer>
            Generated by PySyMex v{version} •
            <a href="https://github.com/darkoss1/pysymex" style="color: var(--accent);">GitHub</a>
        </footer>
    </div>
    <script>
        document.querySelectorAll('.collapsible').forEach(el => {{
            el.addEventListener('click', function() {{
                this.classList.toggle('collapsed');
                const content = this.nextElementSibling;
                content.classList.toggle('show');
            }});
        }});
        // Expand first issue by default
        const firstCollapsible = document.querySelector('.collapsible');
        if (firstCollapsible) {{
            firstCollapsible.nextElementSibling.classList.add('show');
        }}
    </script>
</body>
</html>"""


def _format_issue_html(issue: IssueReport) -> str:
    """Format a single issue as HTML."""

    severity_class = (
        issue.severity if issue.severity in ("critical", "warning", "info") else "critical"
    )

    location = ""

    if issue.file_path:
        location = html.escape(issue.file_path)

        if issue.line_number:
            location += f":{issue.line_number}"

    input_html = ""

    if issue.triggering_input:
        inputs = ", ".join(
            f"<code>{html.escape(k)} = {html.escape(repr(v))}</code>"
            for k, v in issue.triggering_input.items()
        )

        input_html = f"""
            <div class="input-example">
                <strong>Triggering Input:</strong> {inputs}
            </div>
        """

    return f"""
        <div class="issue {severity_class}">
            <div class="issue-header">
                <span class="issue-type">
                    <span class="badge {severity_class}">{html.escape(issue.severity)}</span>
                    {html.escape(issue.issue_type)}
                </span>
                <span class="issue-location">{location}</span>
            </div>
            <div class="issue-message">{html.escape(issue.message)}</div>
            {input_html}
        </div>
    """


def _format_issues_section(issues: list[IssueReport]) -> str:
    """Format all issues as HTML."""

    if not issues:
        return """
            <div class="no-issues">
                <div class="icon">✓</div>
                <h3>No Issues Found</h3>
                <p>All explored paths completed without detecting any problems.</p>
            </div>
        """

    return "\n".join(_format_issue_html(issue) for issue in issues)


def _format_resources_html(resources: ResourceSnapshot | None) -> str:
    """Format resource usage as HTML."""

    if resources is None:
        return "<p>No resource data available.</p>"

    items = [
        ("Paths", resources.paths_explored, ""),
        ("Max Depth", resources.max_depth_reached, ""),
        ("Iterations", resources.iterations, ""),
        ("Time", f"{resources.elapsed_time:.2f}", "s"),
        ("Solver Calls", resources.solver_calls, ""),
        ("Cache Hits", resources.cache_hits, ""),
    ]

    html_parts: list[str] = []

    for label, value, unit in items:
        html_parts.append(f"""
            <div class="resource-item">
                <div class="value">{value}{unit}</div>
                <div class="label">{label}</div>
            </div>
        """)

    return "\n".join(html_parts)


def generate_html_report(report: AnalysisReport) -> str:
    """Generate a standalone HTML report.
    Args:
        report: The analysis report data
    Returns:
        Complete HTML document as string
    """

    if report.error_message:
        status = "Error"

        status_class = "critical"

    elif report.partial:
        status = "Partial"

        status_class = "warning"

    elif report.success:
        status = "Complete"

        status_class = "success"

    else:
        status = "Failed"

        status_class = "critical"

    issue_count = len(report.issues)

    issues_class = "critical" if issue_count > 0 else "success"

    max_depth = report.resources.max_depth_reached if report.resources else 0

    html_content = HTML_TEMPLATE.format(
        title=html.escape(report.title),
        file_path=html.escape(report.file_path),
        function_name=html.escape(report.function_name),
        timestamp=html.escape(report.timestamp),
        duration=report.duration_seconds,
        issue_count=issue_count,
        issues_class=issues_class,
        paths_explored=report.paths_explored,
        max_depth=max_depth,
        status=status,
        status_class=status_class,
        issues_html=_format_issues_section(report.issues),
        resources_html=_format_resources_html(report.resources),
        version=html.escape(report.version),
    )

    return html_content


def save_html_report(report: AnalysisReport, output_path: Path) -> None:
    """Save HTML report to file.
    Args:
        report: The analysis report data
        output_path: Path to save the HTML file
    """

    html_content = generate_html_report(report)

    output_path.write_text(html_content, encoding="utf-8")


def create_report_from_result(
    result: Any,
    file_path: str,
    function_name: str,
    duration: float,
) -> AnalysisReport:
    """Create an AnalysisReport from an analysis result.
    Args:
        result: The analysis result object
        file_path: Path to analyzed file
        function_name: Name of analyzed function
        duration: Analysis duration in seconds
    Returns:
        AnalysisReport ready for HTML generation
    """

    issues: list[IssueReport] = []

    if hasattr(result, "issues"):
        for issue in result.issues:
            severity: str = "critical"

            if hasattr(issue, "severity"):
                severity = str(issue.severity)

            elif "warning" in str(type(issue)).lower():
                severity = "warning"

            issues.append(
                IssueReport(
                    severity=severity,
                    issue_type=str(getattr(issue, "type", type(issue).__name__)),
                    message=getattr(issue, "message", str(issue)),
                    file_path=file_path,
                    line_number=getattr(issue, "line_number", None),
                    function_name=function_name,
                    triggering_input=getattr(issue, "triggering_input", None),
                )
            )

    resources = None

    if hasattr(result, "paths_explored"):
        resources = ResourceSnapshot(
            paths_explored=result.paths_explored,
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
        paths_explored=getattr(result, "paths_explored", 0),
        paths_completed=getattr(result, "paths_completed", 0),
        resources=resources,
        success=not issues,
        partial=getattr(result, "partial", False),
    )


__all__ = [
    "IssueReport",
    "AnalysisReport",
    "generate_html_report",
    "save_html_report",
    "create_report_from_result",
]
