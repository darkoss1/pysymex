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

"""Rich-powered console sink for engine statistics.

Provides real-time interactive terminal visualization of statistics
(e.g., path rate, peak memory, and SMT counters) with graceful fallbacks to
plain text.
"""

from __future__ import annotations

from typing import Any

from pysymex._internal.logging.root import get_logger

from .base import StatsSink

logger = get_logger(__name__)

# Metric display names and formatting for the Rich table.
_METRIC_LABELS: dict[str, str] = {
    "total_paths_explored": "Paths Explored",
    "path_exploration_rate": "Path Rate (inst.)",
    "path_exploration_rate_avg": "Path Rate (avg)",
    "engine_activity_rate": "Stats Event Rate",
    "max_memory_mb": "Peak Memory",
    "avg_memory_mb": "Avg Memory",
    "solver_queries": "Solver Queries",
    "solver_sat": "Solver SAT",
    "solver_unsat": "Solver UNSAT",
    "solver_unknown": "Solver Unknown",
    "solver_total_clauses": "Solver Clauses",
    "solver_avg_clauses": "Avg Solver Clauses",
}

_UNIT_SUFFIXES: dict[str, str] = {
    "path_exploration_rate": " paths/s",
    "path_exploration_rate_avg": " paths/s",
    "engine_activity_rate": " events/s",
    "max_memory_mb": " MB",
    "avg_memory_mb": " MB",
}


def format_metric_value(key: str, value: float | str) -> str:
    """Format a metric value with its unit suffix."""
    suffix = _UNIT_SUFFIXES.get(key, "")
    if isinstance(value, float):
        if key.endswith("_mb"):
            return f"{value:.1f}{suffix}"
        if key.endswith("_ratio"):
            return f"{value:.4f}"
        return f"{value:,.1f}{suffix}"
    return f"{value}{suffix}"


class ConsoleSink(StatsSink):
    """Rich-powered live-streaming console sink for engine statistics.

    Uses ``rich.live.Live`` to render a continuously-updating stats table
    to stderr so it does not interfere with scan output on stdout.
    Falls back to a plain-text final summary when Rich is unavailable
    or when the output is not a terminal.
    """

    def __init__(self) -> None:
        """Initialize the console statistics sink.

        Prepares initial console, live display instance variables, and internal metrics caching.
        """
        self.live: Any | None = None
        self._console: Any | None = None
        self.last_metrics: dict[str, float | int | str] = {}
        self.started = False

    def start(self) -> None:
        """Begin the Rich Live display on stderr."""
        if self.started:
            return
        self.started = True
        try:
            from rich.console import Console
            from rich.live import Live

            self._console = Console(stderr=True, force_terminal=None)
            if not self._console.is_terminal:
                raise ImportError("stderr is not a TTY")
            self._console.print()
            self._console.print()
            self.live = Live(
                self.build_table({}),
                console=self._console,
                refresh_per_second=4,
                transient=False,
            )
            self.live.start()
        except Exception:
            # Rich unavailable or non-TTY: fall back to plain text at stop().
            logger.debug("Rich Live display unavailable, will use plain-text fallback")
            self.live = None
            self._console = None

    def stop(self) -> None:
        """Stop the Rich Live display and print a final summary."""
        if not self.started:
            return
        self.started = False
        if self.live is not None:
            try:
                self.live.update(self.build_table(self.last_metrics))
                self.live.stop()
            except Exception:
                logger.debug("Rich Live display stop failed", exc_info=True)
            self.live = None
        else:
            # Print a final, static summary of the last known metrics.
            self._print_final_summary(self.last_metrics)

    def write(self, metrics: dict[str, float | int | str]) -> None:
        """Update the live display with the latest metrics snapshot."""
        self.last_metrics = dict(metrics)
        if self.live is not None:
            try:
                self.live.update(self.build_table(metrics))
            except Exception:
                logger.debug("Rich Live metrics update failed", exc_info=True)

    @staticmethod
    def build_table(metrics: dict[str, float | int | str]) -> Any:
        """Build a Rich Table wrapped in a Panel from the current metrics dict."""
        try:
            from rich import box
            from rich.panel import Panel
            from rich.table import Table

            table = Table(
                box=box.SIMPLE,
                border_style="dim cyan",
                header_style="bold white",
                show_lines=False,
                padding=(0, 1),
                min_width=46,
            )
            table.add_column("Metric", style="bold white", min_width=20)
            table.add_column("Value", style="cyan", justify="right", min_width=18)

            if not metrics:
                table.add_row("[dim]Waiting for data...[/dim]", "")
            else:
                for key in _METRIC_LABELS:
                    if key not in metrics:
                        continue
                    value = metrics[key]
                    label = _METRIC_LABELS[key]
                    formatted = format_metric_value(key, value)

                    # Color-code memory values when they get high.
                    if key.endswith("_mb") and isinstance(value, (int, float)):
                        if value > 500:
                            formatted = f"[bold red]{formatted}[/bold red]"
                        elif value > 200:
                            formatted = f"[yellow]{formatted}[/yellow]"
                        else:
                            formatted = f"[green]{formatted}[/green]"

                    table.add_row(label, formatted)

                # Show any extra metrics not in the predefined list.
                for key, value in metrics.items():
                    if key in _METRIC_LABELS:
                        continue
                    label = key.replace("_", " ").title()
                    formatted = format_metric_value(key, value)
                    table.add_row(f"[dim]{label}[/dim]", f"[dim]{formatted}[/dim]")

            panel = Panel(
                table,
                title="[bold cyan] Engine Statistics [/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                expand=False,
            )
            return panel
        except ImportError:
            # If rich is somehow missing at runtime, return a plain string.
            return plain_text_metrics(metrics)

    def _print_final_summary(self, metrics: dict[str, float | int | str]) -> None:
        """Print a static final summary, trying Rich before plain text."""
        if not metrics:
            return
        try:
            from rich.console import Console

            console = Console(stderr=True)
            console.print()
            console.print()
            table = self.build_table(metrics)
            console.print(table, end="")
        except Exception:
            # Pure plain-text fallback.
            import sys
            sys.stderr.write("\n\n" + plain_text_metrics(metrics) + "\n")


def plain_text_metrics(metrics: dict[str, float | int | str]) -> str:
    """Format metrics as plain text (fallback when Rich is unavailable)."""
    lines = ["=== Engine Statistics ==="]
    for key, value in metrics.items():
        label = _METRIC_LABELS.get(key, key.replace("_", " ").title())
        if isinstance(value, float):
            lines.append(f"  {label}: {value:.4f}")
        else:
            lines.append(f"  {label}: {value}")
    return "\n".join(lines)
