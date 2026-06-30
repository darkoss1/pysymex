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

"""Benchmark result rendering for terminal and automation outputs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pysymex._internal.benchmarks.suite.types import (
    BenchmarkEvent,
    BenchmarkResult,
    BenchmarkStatus,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class BenchmarkReporter:
    """Renders benchmark results in various output formats.

    All methods are ``@staticmethod``; no instance state is needed.
    """

    @staticmethod
    def to_text(results: list[BenchmarkResult]) -> str:
        """Return the human-readable terminal report."""
        lines = ["", "=" * 88, "pysymex Benchmark Results", "=" * 88]
        if not results:
            lines.append("No benchmark cases matched the requested filters.")
            lines.append("=" * 88)
            return "\n".join(lines)

        for result in results:
            status = result.status.value.upper()
            lines.append(f"\n{result.name} ({result.category.name}, {status})")
            lines.append("-" * 56)
            lines.append(f"  Mean time:     {result.mean_seconds * 1000:.2f} ms")
            lines.append(f"  Std dev:       {result.stddev_seconds * 1000:.2f} ms")
            lines.append(
                f"  Min/Max:       {result.min_seconds * 1000:.2f}/{result.max_seconds * 1000:.2f} ms",
            )
            lines.append(f"  Peak memory:   {result.peak_memory_mb:.2f} MB")
            lines.append(f"  Throughput:    {result.throughput:.0f} instr/sec")
            lines.append(f"  Solver calls:  {result.solver_calls}")
            if result.issue_count > 0:
                lines.append(f"  Issues:        {result.issue_count}")
            if result.paths_explored > 0:
                lines.append(f"  Paths/sec:     {result.paths_per_second:.2f}")
            if result.tags:
                lines.append(f"  Tags:          {', '.join(result.tags)}")
            lines.append(f"  Stability:     {result.stability}")
            if result.failure:
                lines.append(f"  Failure:       {result.failure}")

        completed = sum(1 for result in results if result.status is BenchmarkStatus.COMPLETED)
        failed = len(results) - completed
        slowest = max(results, key=lambda result: result.mean_seconds)
        lines.extend(
            [
                "",
                "-" * 88,
                f"Completed: {completed}  Failed: {failed}  Slowest: "
                f"{slowest.name} ({slowest.mean_seconds * 1000:.2f} ms)",
                "=" * 88,
            ],
        )
        return "\n".join(lines)

    @staticmethod
    def to_json(results: list[BenchmarkResult]) -> str:
        """Convert results to JSON."""
        logger.verbose("Rendering %d benchmark result(s) to JSON", len(results))
        return json.dumps(
            [r.to_dict() for r in results],
            indent=2,
        )

    @staticmethod
    def to_json_file(results: list[BenchmarkResult], path: Path) -> None:
        """Write results to JSON file."""
        logger.verbose("Writing %d benchmark result(s) to %s", len(results), path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(BenchmarkReporter.to_json(results), encoding="utf-8")

    @staticmethod
    def to_file(results: list[BenchmarkResult], path: Path, *, output_format: str) -> None:
        """Write results in the requested report format."""
        logger.verbose(
            "Writing %d benchmark result(s) as %s to %s",
            len(results),
            output_format,
            path,
        )
        if output_format == "json":
            content = BenchmarkReporter.to_json(results)
        elif output_format == "markdown":
            content = BenchmarkReporter.to_markdown(results)
        else:
            content = BenchmarkReporter.to_text(results)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{content}\n", encoding="utf-8")

    @staticmethod
    def to_markdown(results: list[BenchmarkResult]) -> str:
        """Convert results to Markdown table."""
        logger.verbose("Rendering %d benchmark result(s) to Markdown", len(results))
        lines = [
            "| Benchmark | Category | Status | Mean (ms) | Std Dev | Peak Memory (MB) | Issues | Throughput |",
            "|-----------|----------|--------|-----------|---------|------------------|--------|------------|",
        ]
        for r in results:
            lines.append(
                f"| {r.name} | {r.category.name} | {r.status.value} | "
                f"{r.mean_seconds * 1000:.2f} | {r.stddev_seconds * 1000:.2f} | "
                f"{r.peak_memory_mb:.2f} | {r.issue_count} | {r.throughput:.0f} instr/s |",
            )
        return "\n".join(lines)

    @staticmethod
    def format_inventory(results: list[str]) -> str:
        """Render benchmark case names for ``pysymex benchmark --list``."""
        if not results:
            return "\nNo benchmark cases matched the requested filters."
        lines = ["", "Benchmark Cases", ""]
        lines.extend(f"  {name}" for name in results)
        return "\n".join(lines)

    @staticmethod
    def progress_line(event: BenchmarkEvent) -> str:
        """Return a compact live progress line."""
        prefix = f"Benchmark: [{event.completed}/{event.total}]"
        if event.phase == "iteration":
            return (
                f"{prefix} {event.benchmark_name} iteration {event.message}: "
                f"{event.elapsed_seconds * 1000:.2f} ms"
            )
        if event.phase == "finished":
            return f"{prefix} {event.benchmark_name} done: {event.elapsed_seconds * 1000:.2f} ms"
        if event.phase == "failed":
            return f"{prefix} {event.benchmark_name} failed: {event.message}"
        return f"{prefix} {event.phase} {event.benchmark_name} ({event.category.name})"
