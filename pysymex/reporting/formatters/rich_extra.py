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

"""Additional Rich formatter renderers."""

from __future__ import annotations

from pysymex.reporting.formatters.protocols import VerifiedResultLike
from pysymex.reporting.formatters.text import TextFormatter


class RichFormatterExtraMixin:
    """Verification renderers for RichFormatter."""

    color: bool
    verbose: bool

    def format_verify(self, result: VerifiedResultLike) -> str:
        """Format a VerifiedExecutionResult with Rich."""
        try:
            from io import StringIO
            from rich import box
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table

            console = Console(file=StringIO(), force_terminal=True, width=100)
            console.print(
                Panel(
                    f"Verified Execution: [bold cyan]{result.function_name}[/bold cyan]",
                    border_style="cyan",
                    box=box.ROUNDED,
                )
            )
            console.print()

            if result.degraded_passes:
                console.print("[bold yellow]Analysis degraded:[/bold yellow]")
                console.print(", ".join(result.degraded_passes))
                console.print()

            if result.termination_proof:
                status_obj = result.termination_proof.status
                status_name = getattr(status_obj, "name", None)
                status = status_name if isinstance(status_name, str) else str(status_obj)
                status_style = (
                    "green" if status == "PROVED" else "yellow" if status == "UNKNOWN" else "red"
                )
                console.print(
                    f"[bold]Termination:[/bold] [{status_style}]{status}[/{status_style}] - {result.termination_proof.message}"
                )
                console.print()

            if result.arithmetic_issues:
                console.print(
                    f"[bold red]Arithmetic Issues ({len(result.arithmetic_issues)}):[/bold red]"
                )
                for ai in result.arithmetic_issues:
                    format_fn = getattr(ai, "format", None)
                    msg = str(format_fn()).strip() if callable(format_fn) else str(ai)
                    console.print(f"  • {msg}")
                console.print()

            if result.contract_issues:
                console.print(
                    f"[bold red]Contract Issues ({len(result.contract_issues)}):[/bold red]"
                )
                for ci in result.contract_issues:
                    format_fn = getattr(ci, "format", None)
                    msg = str(format_fn()).strip() if callable(format_fn) else str(ci)
                    console.print(f"  • {msg}")
                console.print()

            summary = Table.grid(padding=(0, 2))
            summary.add_column(style="bold white")
            summary.add_column(style="cyan")
            summary.add_row("Paths Explored:", str(result.paths_explored))
            summary.add_row("Paths Completed:", str(result.paths_completed))
            console.print(summary)

            return console.file.getvalue()
        except ImportError:
            return TextFormatter(color=self.color, verbose=self.verbose).format_verify(result)


__all__ = ["RichFormatterExtraMixin"]
