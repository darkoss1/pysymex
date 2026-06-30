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

"""Rich symbolic scan text formatting."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from pysymex._internal.analysis.records import iter_trigger_assignments, normalize_trigger_input
from pysymex._internal.config.defaults import VERSION

if TYPE_CHECKING:
    from collections.abc import Sequence


class SymbolicRichMixin:
    """Rich renderer for symbolic scan results."""

    def _format_symbolic_rich(
        self,
        results: Sequence[Any],
        total: int,
        reproduce: bool,
        duration: float,
    ) -> str:
        """Format symbolic execution scan results using rich terminal components.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
            duration (float): Execution duration in seconds.

        Returns:
            str: Rich text formatted report with panels, tables, and colors.

        """
        from io import StringIO

        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(file=StringIO(), force_terminal=True, width=80)
        console.print()
        console.print()

        header = Panel(
            "[bold cyan]pysymex - formal verification report[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
        )
        console.print(header)
        console.print()

        valid_results = [r for r in results if hasattr(r, "elapsed_time")]
        error_results = [r for r in results if getattr(r, "error", None)]
        degraded_results = [r for r in results if getattr(r, "degraded_passes", [])]
        console.print()

        if error_results:
            console.print("[bold red]SCAN ERRORS[/bold red]")
            console.print("[dim]" + "─" * 60 + "[/dim]")
            for r in error_results:
                console.print(f"[bold red]File:[/bold red] {r.file_path}")
                console.print(f"[red]Error:[/red] {r.error}")
                console.print()
            console.print()

        if degraded_results:
            console.print("[bold yellow]DEGRADED ANALYSES[/bold yellow]")
            for result in degraded_results:
                console.print(f"[bold yellow]File:[/bold yellow] {result.file_path}")
                console.print(f"[yellow]Markers:[/yellow] {', '.join(result.degraded_passes)}")
            console.print()

        if total > 0:
            console.print(f"[bold red]ISSUES FOUND ({total})[/bold red]")
            console.print("[dim]" + "─" * 60 + "[/dim]")

            for scan_result in valid_results:
                issues = getattr(scan_result, "issues", [])
                if not issues:
                    continue

                file_path = getattr(scan_result, "file_path", "unknown")
                console.print(f"📁 [bold cyan]{file_path}[/bold cyan]")

                for issue in issues:
                    if not isinstance(issue, dict):
                        continue
                    issue_dict = cast("dict[str, Any]", issue)
                    kind = issue_dict.get("kind", "UNKNOWN")
                    line = issue_dict.get("line", "?")
                    message = issue_dict.get("message", "")

                    severity_str = str(issue_dict.get("severity", "")).upper()
                    if "CRITICAL" in severity_str or "HIGH" in severity_str or "ERROR" in severity_str:
                        color = "red"
                    elif "MEDIUM" in severity_str or "WARNING" in severity_str:
                        color = "yellow"
                    elif "INFO" in severity_str:
                        color = "green"
                    elif "LOW" in severity_str:
                        color = "blue"
                    else:
                        color = "red"

                    issue_details = (
                        f"[bold {color}]Location:[/bold {color}] {file_path}:{line}\n"
                        f"[bold {color}]Type:[/bold {color}]    {kind}\n"
                        f"[bold {color}]Error:[/bold {color}]    {message}"
                    )

                    trigger_assignments = iter_trigger_assignments(issue_dict.get("counterexample"))
                    if trigger_assignments:
                        issue_details += f"\n[bold {color}]Trigger:[/bold {color}]  [bold yellow]"
                        for name, value in trigger_assignments:
                            issue_details += f"{name} = {value}, "
                        issue_details = issue_details.rstrip(", ")
                        issue_details += "[/bold yellow]"

                    issue_panel = Panel(
                        issue_details,
                        title=f"[bold {color}][ {kind} ][/bold {color}]",
                        title_align="left",
                        border_style=color,
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                    console.print(issue_panel)
                console.print()

            if reproduce:
                from pysymex._internal.analysis.detectors.detector.types import Issue, IssueKind
                from pysymex._internal.reporting.reproduction.generation import (
                    ReproductionGenerator,
                )

                console.print("[bold yellow]Reproduction Scripts:[/bold yellow]")

                for scan_result in valid_results:
                    issues = getattr(scan_result, "issues", [])
                    file_path = getattr(scan_result, "file_path", "unknown")
                    for issue in issues:
                        if not isinstance(issue, dict):
                            continue
                        issue_dict = cast("dict[str, Any]", issue)
                        ce = normalize_trigger_input(issue_dict.get("counterexample"))
                        if ce is not None:
                            issue_kind = IssueKind.__members__.get(
                                str(issue_dict.get("kind", IssueKind.UNKNOWN)),
                                IssueKind.UNKNOWN,
                            )
                            issue_obj = Issue(
                                kind=issue_kind,
                                message=str(issue_dict.get("message", "")),
                                function_name=str(issue_dict.get("function_name", "unknown")),
                                class_name=issue_dict.get("class_name")
                                if isinstance(issue_dict.get("class_name", ""), str)
                                else None,
                                counterexample=ce,
                                filename=str(file_path),
                                line_number=int(issue_dict.get("line", 0)),
                                pc=0,
                                constraints=[],
                            )
                            gen = ReproductionGenerator()
                            script_path = gen.generate_script(issue_obj)
                            if script_path:
                                console.print(f"  * {script_path}")
        elif not results:
            console.print("[yellow]No files were scanned.[/yellow]")
            console.print()
        elif not error_results and not degraded_results:
            console.print("[green]No issues found![/green]")
            console.print()

        console.print("[dim]" + "─" * 80 + "[/dim]")

        summary_grid = Table.grid(padding=(0, 3))
        summary_grid.add_column(style="bold white", justify="left")
        summary_grid.add_column(style="cyan", justify="right")

        summary_grid.add_row("Files scanned:", str(len(results)))
        summary_grid.add_row(
            "Issues found:",
            f"[bold red]{total}[/bold red]" if total > 0 else "[green]0[/green]",
        )

        if error_results:
            summary_grid.add_row("Scan errors:", f"[bold red]{len(error_results)}[/bold red]")
        if degraded_results:
            summary_grid.add_row(
                "Degraded scans:",
                f"[bold yellow]{len(degraded_results)}[/bold yellow]",
            )

        if valid_results:
            mems = [r.avg_memory_mb for r in valid_results if getattr(r, "avg_memory_mb", 0) > 0]
            avg_mem = sum(mems) / len(mems) if mems else 0.0
            summary_grid.add_row("Execution time:", f"{duration:.2f}s")
            summary_grid.add_row("Memory (avg):", f"{avg_mem:.2f} MB")

        summary_panel = Panel(
            summary_grid,
            title="[bold cyan] Summary [/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            expand=False,
        )
        console.print(summary_panel)
        console.print()
        console.print(f"pysymex v{VERSION} | https://github.com/darkoss1/pysymex")
        return console.file.getvalue()
