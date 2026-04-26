# pysymex: Python Symbolic Execution & Formal Verification
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

"""Output formatters for pysymex results."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING

from pysymex import __version__

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue
    from pysymex.execution.executors import ExecutionResult


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
    """Plain text formatter with enhanced readability.

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
        lines.append("  pysymex — Formal Verification Report")
        lines.append("══════════════════════════════════════════════════════════════════════")
        lines.append("")
        lines.append(f"  File:      {result.source_file}")
        lines.append(f"  Function:  {result.function_name}()")
        lines.append(f"  Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
        lines.append(f"  pysymex v{__version__} | https://github.com/darkoss1/pysymex")
        lines.append("")
        return "\n".join(lines)


class JSONFormatter(Formatter):
    """JSON formatter for machine-readable output.

    Attributes:
        indent: Number of spaces for JSON indentation.
        include_constraints: Whether to include raw Z3 constraints.
    """

    name = "json"
    extension = ".json"

    def __init__(self, indent: int = 2, include_constraints: bool = False) -> None:
        """Initialise the JSON formatter.

        Args:
            indent: JSON indentation level.
            include_constraints: Embed Z3 constraint strings.
        """
        self.indent = indent
        self.include_constraints = include_constraints

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a JSON document.

        Args:
            result: Execution result to serialise.

        Returns:
            Pretty-printed JSON string.
        """
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

    def _format_issue(self, issue: Issue) -> dict[str, object]:
        """Serialise a single *issue* to a JSON-friendly dict."""
        data: dict[str, object] = {
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
        from pysymex.reporting.html import (
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
            "# pysymex - Symbolic Execution Report",
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
            lines.append("## [OK] No Issues Found")
            lines.append("")
            lines.append("The symbolic execution did not detect any potential issues.")
        return "\n".join(lines)


class RichFormatter(Formatter):
    """Rich formatter with colored panels and tables for terminal output."""

    name = "rich"
    extension = ".txt"

    def __init__(self, color: bool = True, verbose: bool = False) -> None:
        """Initialise the rich formatter.

        Args:
            color: Enable colored output.
            verbose: Include extra detail.
        """
        self.color = color
        self.verbose = verbose

    def format(self, result: ExecutionResult) -> str:
        """Format *result* as a rich-styled text report.

        Args:
            result: Execution result to render.

        Returns:
            Multi-line string with rich markup for terminal display.
        """
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich import box
            from io import StringIO

            console = Console(file=StringIO(), force_terminal=True, width=80)

            # 1. Main Header
            header = Panel(
                "pysymex - Formal Verification Report",
                border_style="cyan",
                box=box.ROUNDED,
            )
            console.print(header)
            console.print()

            # 2. Crash Section
            if result.issues:
                console.print(f"[bold red]ISSUES FOUND ({len(result.issues)})[/bold red]")
                console.print("[dim]" + "─" * 60 + "[/dim]")

                for issue in result.issues:
                    crash_details = (
                        f"[bold red]Location:[/bold red] {result.source_file}:{issue.line_number} in {result.function_name}()\n"
                        f"[bold red]Type:[/bold red]    {issue.kind.name}\n"
                        f"[bold red]Error:[/bold red]    {issue.message}"
                    )

                    counterexample = issue.get_counterexample()
                    if counterexample:
                        crash_details += f"\n[bold red]Trigger:[/bold red]  [bold yellow]"
                        for name, value in sorted(counterexample.items()):
                            crash_details += f"{name} = {value}, "
                        crash_details = crash_details.rstrip(", ")
                        crash_details += "[/bold yellow]"

                    crash_panel = Panel(
                        crash_details,
                        title=f"[bold red][ {issue.kind.name} ][/bold red]",
                        title_align="left",
                        border_style="red",
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                    console.print(crash_panel)

                console.print()

            # 3. Summary Section
            console.print("[bold blue]SUMMARY[/bold blue]")
            console.print("[dim]" + "─" * 60 + "[/dim]")

            summary_grid = Table.grid(padding=(0, 3))
            summary_grid.add_column(style="bold white", justify="left")
            summary_grid.add_column(style="cyan", justify="right")

            summary_grid.add_row("Paths explored:", str(result.paths_explored))
            summary_grid.add_row("Paths completed:", str(result.paths_completed))
            summary_grid.add_row("Instructions:", str(len(result.coverage)))
            summary_grid.add_row("Execution time:", f"{result.total_time_seconds:.3f}s")
            summary_grid.add_row("", "")

            safe_count = max(0, result.paths_completed - len(result.issues))
            summary_grid.add_row("Proven safe:", f"[green]{safe_count}[/green]")

            crash_count = len(result.issues)
            if result.issues:
                summary_grid.add_row("Issues found:", f"[bold red]{crash_count}[/bold red]")
            else:
                summary_grid.add_row("Issues found:", f"[green]{crash_count}[/green]")

            console.print(summary_grid)
            console.print()
            console.print(f"pysymex v{__version__} | https://github.com/darkoss1/pysymex")

            output = console.file.getvalue()  # type: ignore[attr-access]  # will be fixed later
            return output  # type: ignore[return-value]  # will be fixed later
        except ImportError:
            return TextFormatter(color=self.color, verbose=self.verbose).format(result)


def format_result(
    result: ExecutionResult,
    format_type: str = "text",
    **kwargs: object,
) -> str:
    """
    Format an execution result.
    Args:
        result: The execution result to format
        format_type: One of "text", "json", "html", "markdown", "sarif", "rich"
        **kwargs: Additional formatter options
    Returns:
        Formatted string
    Notes:
        - "text": Human-readable output with icons and formatting
        - "json": Machine-readable JSON for programmatic access
        - "html": Rich HTML report for browsers
        - "markdown": Documentation-friendly format
        - "sarif": SARIF 2.1.0 for CI/CD integration (GitHub, VS Code, etc.)
        - "rich": Rich terminal output with colors and panels
    """
    formatters = {
        "text": TextFormatter,
        "json": JSONFormatter,
        "html": HTMLFormatter,
        "markdown": MarkdownFormatter,
        "md": MarkdownFormatter,
        "rich": RichFormatter,
    }
    if format_type.lower() == "sarif":
        if hasattr(result, "to_sarif"):
            return json.dumps(result.to_sarif(), indent=2)
        return "{}"
    formatter_class = formatters.get(format_type.lower(), TextFormatter)
    if formatter_class is TextFormatter:
        color = kwargs.get("color", True)
        verbose = kwargs.get("verbose", False)
        formatter = TextFormatter(
            color=color if isinstance(color, bool) else True,
            verbose=verbose if isinstance(verbose, bool) else False,
        )
    elif formatter_class is RichFormatter:
        color = kwargs.get("color", True)
        verbose = kwargs.get("verbose", False)
        formatter = RichFormatter(
            color=color if isinstance(color, bool) else True,
            verbose=verbose if isinstance(verbose, bool) else False,
        )
    elif formatter_class is JSONFormatter:
        indent = kwargs.get("indent", 2)
        include_constraints = kwargs.get("include_constraints", False)
        formatter = JSONFormatter(
            indent=indent if isinstance(indent, int) else 2,
            include_constraints=(
                include_constraints if isinstance(include_constraints, bool) else False
            ),
        )
    else:
        formatter = formatter_class()
    return formatter.format(result)
