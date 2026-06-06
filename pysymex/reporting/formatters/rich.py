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

"""Rich terminal reporting formatter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.scan.records import iter_trigger_assignments
from pysymex.config import VERSION
from pysymex.reporting.formatters.base import Formatter
from pysymex.reporting.formatters.rich_extra import RichFormatterExtraMixin
from pysymex.reporting.formatters.text import TextFormatter

if TYPE_CHECKING:
    from pysymex.execution.results.result import ExecutionResult


class RichFormatter(RichFormatterExtraMixin, Formatter):
    """Rich formatter with colored panels and tables for terminal output."""

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
                "pysymex - formal verification report",
                border_style="cyan",
                box=box.ROUNDED,
            )
            console.print(header)
            console.print()

            if result.degraded_passes:
                console.print("[bold yellow]ANALYSIS DEGRADED[/bold yellow]")
                console.print(", ".join(result.degraded_passes))
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

                    counterexample = iter_trigger_assignments(issue.get_counterexample())
                    if counterexample:
                        crash_details += "\n[bold red]Trigger:[/bold red]  [bold yellow]"
                        for name, value in counterexample:
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

            if result.degraded_passes:
                summary_grid.add_row("Analysis status:", "[yellow]Degraded[/yellow]")
            else:
                safe_count = max(0, result.paths_completed - len(result.issues))
                summary_grid.add_row("Proven safe:", f"[green]{safe_count}[/green]")

            crash_count = len(result.issues)
            if result.issues:
                summary_grid.add_row("Issues found:", f"[bold red]{crash_count}[/bold red]")
            else:
                summary_grid.add_row("Issues found:", f"[green]{crash_count}[/green]")

            console.print(summary_grid)
            console.print()
            console.print(f"pysymex v{VERSION} | https://github.com/darkoss1/pysymex")

            return console.file.getvalue()
        except ImportError:
            return TextFormatter(color=self.color, verbose=self.verbose).format(result)


__all__ = ["RichFormatter"]
