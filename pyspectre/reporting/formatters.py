"""Output formatters for PySpectre results."""

from __future__ import annotations
import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyspectre.analysis.detectors import Issue
    from pyspectre.execution.executor import ExecutionResult


class Formatter(ABC):
    """Base class for output formatters."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def format(self, result: ExecutionResult) -> str:
        """Format the execution result."""

    def save(self, result: ExecutionResult, filepath: str) -> None:
        """Save formatted result to file."""
        content = self.format(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)


class TextFormatter(Formatter):
    """Plain text formatter with enhanced readability."""

    name = "text"
    extension = ".txt"
    SEVERITY_ICONS = {
        "DIVISION_BY_ZERO": "🔴 CRITICAL",
        "ASSERTION_ERROR": "🔴 CRITICAL",
        "NULL_DEREFERENCE": "🔴 CRITICAL",
        "INDEX_ERROR": "🟠 HIGH",
        "KEY_ERROR": "🟠 HIGH",
        "TYPE_ERROR": "🟡 MEDIUM",
        "ATTRIBUTE_ERROR": "🟡 MEDIUM",
        "UNREACHABLE": "🔵 INFO",
        "INVALID_ARGUMENT": "🔵 INFO",
    }

    def __init__(self, color: bool = True, verbose: bool = False):
        self.color = color
        self.verbose = verbose

    def format(self, result: ExecutionResult) -> str:
        lines = []
        lines.append("")
        lines.append("╔" + "═" * 58 + "╗")
        lines.append("║" + "  🔮 PySpectre - Symbolic Execution Report".center(58) + "║")
        lines.append("╚" + "═" * 58 + "╝")
        lines.append("")
        lines.append(f"  📁 File:      {result.source_file}")
        lines.append(f"  🎯 Function:  {result.function_name}()")
        lines.append(f"  🕐 Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("┌─ Statistics " + "─" * 45 + "┐")
        lines.append(
            f"│  Paths explored:   {result.paths_explored:<8}  Paths completed: {result.paths_completed:<8} │"
        )
        lines.append(
            f"│  Instructions:     {len(result.coverage):<8}  Execution time:  {result.total_time_seconds:.3f}s       │"
        )
        lines.append("└" + "─" * 58 + "┘")
        lines.append("")
        if result.issues:
            issue_count = len(result.issues)
            critical_count = sum(
                1
                for i in result.issues
                if i.kind.name in ("DIVISION_BY_ZERO", "ASSERTION_ERROR", "NULL_DEREFERENCE")
            )
            lines.append(
                f"┌─ ⚠️  Issues Found: {issue_count} " + "─" * (38 - len(str(issue_count))) + "┐"
            )
            if critical_count:
                lines.append(
                    f"│  🔴 Critical: {critical_count}"
                    + " " * (43 - len(str(critical_count)))
                    + "│"
                )
            lines.append("└" + "─" * 58 + "┘")
            lines.append("")
            for i, issue in enumerate(result.issues, 1):
                severity = self.SEVERITY_ICONS.get(issue.kind.name, "⚪ UNKNOWN")
                lines.append(f"  [{i}] {severity}")
                lines.append(f"      Type: {issue.kind.name}")
                lines.append(f"      {issue.message}")
                if issue.line_number:
                    lines.append(f"      📍 Line {issue.line_number}")
                counterexample = issue.get_counterexample()
                if counterexample:
                    lines.append("      ↳ Counterexample (values that trigger bug):")
                    for name, value in sorted(counterexample.items()):
                        lines.append(f"          {name} = {value}")
                lines.append("")
        else:
            lines.append("┌" + "─" * 58 + "┐")
            lines.append("│" + "  ✅ No issues found!".center(58) + "│")
            lines.append("│" + "  Analysis complete.".center(58) + "│")
            lines.append("└" + "─" * 58 + "┘")
            lines.append("")
        lines.append("─" * 60)
        lines.append("  PySpectre v0.3.0a0 | https://github.com/darkoss1/pyspecter")
        lines.append("")
        return "\n".join(lines)


class JSONFormatter(Formatter):
    """JSON formatter for machine-readable output."""

    name = "json"
    extension = ".json"

    def __init__(self, indent: int = 2, include_constraints: bool = False):
        self.indent = indent
        self.include_constraints = include_constraints

    def format(self, result: ExecutionResult) -> str:
        data = {
            "meta": {
                "tool": "PySpectre",
                "version": "1.0.0",
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
                "has_critical": any(
                    i.kind.name in ("DIVISION_BY_ZERO", "ASSERTION_ERROR") for i in result.issues
                ),
            },
            "environment": {
                "python_version": "3.x",
            },
        }
        return json.dumps(data, indent=self.indent, default=str)

    def _format_issue(self, issue: Issue) -> dict[str, Any]:
        data = {
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


class HTMLFormatter(Formatter):
    """HTML formatter for web display."""

    name = "html"
    extension = ".html"

    def format(self, result: ExecutionResult) -> str:
        issues_html = self._format_issues(result.issues)
        style = """
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #1f2937;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-green: #22c55e;
            --accent-yellow: #eab308;
        } 
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        } 
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        } 
        .container {
            max-width: 1200px;
            margin: 0 auto;
        } 
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            border-radius: 12px;
            border: 1px solid #374151;
        } 
        h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--accent-blue), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        } 
        .subtitle {
            color: var(--text-secondary);
        } 
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        } 
        .stat-card {
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid #374151;
            text-align: center;
        } 
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-blue);
        } 
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
        } 
        .issues-section {
            margin-top: 2rem;
        } 
        .section-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        } 
        .issue {
            background: var(--bg-card);
            border-radius: 8px;
            border-left: 4px solid var(--accent-red);
            padding: 1.5rem;
            margin-bottom: 1rem;
        } 
        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        } 
        .issue-kind {
            background: var(--accent-red);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: bold;
        } 
        .issue-location {
            color: var(--text-secondary);
            font-size: 0.9rem;
        } 
        .issue-message {
            font-size: 1.1rem;
            margin-bottom: 1rem;
        } 
        .counterexample {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.9rem;
        } 
        .counterexample h4 {
            color: var(--accent-yellow);
            margin-bottom: 0.5rem;
        } 
        .no-issues {
            background: var(--bg-card);
            border-left: 4px solid var(--accent-green);
            padding: 2rem;
            border-radius: 8px;
            text-align: center;
        } 
        .no-issues-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        } 
        footer {
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #374151;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        } 
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySpectre Report - {result.function_name}</title>
    <style>
        {style}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔮 PySpectre</h1>
            <p class="subtitle">Symbolic Execution Report</p>
            <p class="subtitle" style="margin-top: 0.5rem;">
                <strong>{result.function_name}</strong> | {result.source_file}
            </p>
        </header>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{result.paths_explored}</div>
                <div class="stat-label">Paths Explored</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{result.paths_completed}</div>
                <div class="stat-label">Paths Completed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(result.coverage)}</div>
                <div class="stat-label">Instructions Covered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{result.total_time_seconds:.2f}s</div>
                <div class="stat-label">Execution Time</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {"var(--accent-red)" if result.issues else "var(--accent-green)"}">
                    {len(result.issues)}
                </div>
                <div class="stat-label">Issues Found</div>
            </div>
        </div>
        <div class="issues-section">
            <h2 class="section-header">
                {"⚠️" if result.issues else "✅"} 
                {"Issues Detected" if result.issues else "No Issues Found"}
            </h2>
            {issues_html}
        </div>
        <footer>
            Generated by PySpectre | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </footer>
    </div>
</body>
</html>"""
        return html

    def _format_issues(self, issues: list[Issue]) -> str:
        if not issues:
            return """
            <div class="no-issues">
                <div class="no-issues-icon">✅</div>
                <h3>All Clear!</h3>
                <p>No potential issues were detected in this function.</p>
            </div>
            """
        html_parts = []
        for issue in issues:
            counterexample = issue.get_counterexample()
            counterexample_html = ""
            if counterexample:
                ce_items = "<br>".join(
                    f"{name} = {value}" for name, value in sorted(counterexample.items())
                )
                counterexample_html = f"""
                <div class="counterexample">
                    <h4>Counterexample:</h4>
                    {ce_items}
                </div>
                """
            location = ""
            if issue.line_number:
                location = f"Line {issue.line_number}"
            if issue.function_name:
                location = (
                    f"{issue.function_name}() | {location}"
                    if location
                    else f"{issue.function_name}()"
                )
            html_parts.append(f"""
            <div class="issue">
                <div class="issue-header">
                    <span class="issue-kind">{issue.kind.name.replace("_", " ")}</span>
                    <span class="issue-location">{location}</span>
                </div>
                <p class="issue-message">{issue.message}</p>
                {counterexample_html}
            </div>
            """)
        return "\n".join(html_parts)


class MarkdownFormatter(Formatter):
    """Markdown formatter."""

    name = "markdown"
    extension = ".md"

    def format(self, result: ExecutionResult) -> str:
        lines = [
            "# PySpectre - Symbolic Execution Report",
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
        else:
            lines.append("## ✅ No Issues Found")
            lines.append("")
            lines.append("The symbolic execution did not detect any potential issues.")
        return "\n".join(lines)


def format_result(
    result: ExecutionResult,
    format_type: str = "text",
    **kwargs,
) -> str:
    """
    Format an execution result.
    Args:
        result: The execution result to format
        format_type: One of "text", "json", "html", "markdown", "sarif"
        **kwargs: Additional formatter options
    Returns:
        Formatted string
    Notes:
        - "text": Human-readable output with icons and formatting
        - "json": Machine-readable JSON for programmatic access
        - "html": Rich HTML report for browsers
        - "markdown": Documentation-friendly format
        - "sarif": SARIF 2.1.0 for CI/CD integration (GitHub, VS Code, etc.)
    """
    formatters = {
        "text": TextFormatter,
        "json": JSONFormatter,
        "html": HTMLFormatter,
        "markdown": MarkdownFormatter,
        "md": MarkdownFormatter,
    }
    if format_type.lower() == "sarif":
        if hasattr(result, "to_sarif"):
            return json.dumps(result.to_sarif(), indent=2)
        return "{}"
    formatter_class = formatters.get(format_type.lower(), TextFormatter)
    formatter = formatter_class(**kwargs)
    return formatter.format(result)
