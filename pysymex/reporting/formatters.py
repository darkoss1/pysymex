"""Output formatters for PySyMex results."""

from __future__ import annotations


import json

from abc import ABC, abstractmethod

from datetime import datetime

from typing import TYPE_CHECKING, Any


from pysymex import __version__

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue

    from pysymex.execution.executor import ExecutionResult


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
        lines: list[str] = []

        lines.append("")

        lines.append("╔" + "═" * 58 + "╗")

        lines.append("║" + "  🔮 PySyMex - Symbolic Execution Report".center(58) + "║")

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

        lines.append(f"  PySyMex v{__version__} | https://github.com/darkoss1/pysymex")

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
                "tool": "pysymex",
                "version": __version__,
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
        data: dict[str, Any] = {
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
        from pysymex.reporting.html_report import (
            create_report_from_result,
            generate_html_report,
        )

        report = create_report_from_result(
            result,
            file_path=getattr(result, "source_file", "unknown"),
            function_name=getattr(result, "function_name", "unknown"),
            duration=getattr(result, "total_time_seconds", 0.0),
        )

        return generate_html_report(report)


class MarkdownFormatter(Formatter):
    """Markdown formatter."""

    name = "markdown"

    extension = ".md"

    def format(self, result: ExecutionResult) -> str:
        lines: list[str] = [
            "# PySyMex - Symbolic Execution Report",
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
    **kwargs: Any,
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
