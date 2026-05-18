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

from __future__ import annotations

import logging
import sys
from typing import Any

from .base import StatsSink

logger = logging.getLogger(__name__)

# Metric display names and formatting for the Rich table.
_METRIC_LABELS: dict[str, str] = {
    "total_paths_explored": "Paths Explored",
    "path_exploration_rate": "Path Rate (inst.)",
    "path_exploration_rate_avg": "Path Rate (avg)",
    "engine_activity_rate": "Engine Activity",
    "max_memory_mb": "Peak Memory",
    "avg_memory_mb": "Avg Memory",
    "sat_unsat_ratio": "SAT/UNSAT Ratio",
}

_UNIT_SUFFIXES: dict[str, str] = {
    "path_exploration_rate": " paths/s",
    "path_exploration_rate_avg": " paths/s",
    "engine_activity_rate": " events/s",
    "max_memory_mb": " MB",
    "avg_memory_mb": " MB",
}


def _format_metric_value(key: str, value: float | int | str) -> str:
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
        self._live: Any | None = None
        self._console: Any | None = None
        self._last_metrics: dict[str, float | int | str] = {}
        self._started = False

    def start(self) -> None:
        """Begin the Rich Live display on stderr."""
        if self._started:
            return
        self._started = True
        try:
            from rich.console import Console
            from rich.live import Live

            self._console = Console(stderr=True, force_terminal=None)
            self._live = Live(
                self._build_table({}),
                console=self._console,
                refresh_per_second=4,
                transient=True,
            )
            self._live.start()
        except Exception:
            # Rich unavailable or non-TTY: fall back to plain text at stop().
            logger.debug("Rich Live display unavailable, will use plain-text fallback")
            self._live = None
            self._console = None

    def stop(self) -> None:
        """Stop the Rich Live display and print a final summary."""
        if not self._started:
            return
        self._started = False
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None

        # Print a final, static summary of the last known metrics.
        self._print_final_summary(self._last_metrics)

    def write(self, metrics: dict[str, float | int | str]) -> None:
        """Update the live display with the latest metrics snapshot."""
        self._last_metrics = dict(metrics)
        if self._live is not None:
            try:
                self._live.update(self._build_table(metrics))
            except Exception:
                pass

    @staticmethod
    def _build_table(metrics: dict[str, float | int | str]) -> Any:
        """Build a Rich Table from the current metrics dict."""
        try:
            from rich import box
            from rich.table import Table

            table = Table(
                title="[bold cyan]Engine Statistics[/bold cyan]",
                box=box.ROUNDED,
                border_style="dim cyan",
                title_style="bold cyan",
                header_style="bold white",
                show_lines=False,
                padding=(0, 1),
                min_width=50,
            )
            table.add_column("Metric", style="bold white", min_width=20)
            table.add_column("Value", style="cyan", justify="right", min_width=18)

            if not metrics:
                table.add_row("[dim]Waiting for data...[/dim]", "")
                return table

            for key in _METRIC_LABELS:
                if key not in metrics:
                    continue
                value = metrics[key]
                label = _METRIC_LABELS[key]
                formatted = _format_metric_value(key, value)

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
                formatted = _format_metric_value(key, value)
                table.add_row(f"[dim]{label}[/dim]", f"[dim]{formatted}[/dim]")

            return table
        except ImportError:
            # If rich is somehow missing at runtime, return a plain string.
            return _plain_text_metrics(metrics)

    def _print_final_summary(self, metrics: dict[str, float | int | str]) -> None:
        """Print a static final summary, trying Rich before plain text."""
        if not metrics:
            return
        try:
            from rich.console import Console

            console = Console(stderr=True)
            table = self._build_table(metrics)
            console.print(table, end="")
        except Exception:
            # Pure plain-text fallback.
            print(_plain_text_metrics(metrics), file=sys.stderr)


def _plain_text_metrics(metrics: dict[str, float | int | str]) -> str:
    """Format metrics as plain text (fallback when Rich is unavailable)."""
    lines = ["=== Engine Statistics ==="]
    for key, value in metrics.items():
        label = _METRIC_LABELS.get(key, key.replace("_", " ").title())
        if isinstance(value, float):
            lines.append(f"  {label}: {value:.4f}")
        else:
            lines.append(f"  {label}: {value}")
    return "\n".join(lines)
