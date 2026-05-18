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

"""Benchmark results reporting for pysymex."""

from __future__ import annotations

import json
from pathlib import Path

from pysymex.benchmarks.suite.types import BenchmarkResult


class BenchmarkReporter:
    """Renders benchmark results in various output formats.

    All methods are ``@staticmethod``; no instance state is needed.
    """

    @staticmethod
    def to_console(results: list[BenchmarkResult]) -> None:
        """Print results to console."""
        print("\n" + "=" * 70)
        print("pysymex Benchmark Results")
        print("=" * 70)
        for result in results:
            print(f"\n{result.name} ({result.category.name})")
            print("-" * 40)
            print(f"  Mean time:     {result.mean_seconds * 1000:.2f} ms")
            print(f"  Std dev:       {result.stddev_seconds * 1000:.2f} ms")
            print(
                f"  Min/Max:       {result.min_seconds * 1000:.2f}/{result.max_seconds * 1000:.2f} ms"
            )
            print(f"  Peak memory:   {result.peak_memory_mb:.2f} MB")
            print(f"  Throughput:    {result.throughput:.0f} instr/sec")
            if result.paths_explored > 0:
                print(f"  Paths/sec:     {result.paths_per_second:.2f}")
        print("\n" + "=" * 70)

    @staticmethod
    def to_json(results: list[BenchmarkResult]) -> str:
        """Convert results to JSON."""
        return json.dumps(
            [r.to_dict() for r in results],
            indent=2,
        )

    @staticmethod
    def to_json_file(results: list[BenchmarkResult], path: Path) -> None:
        """Write results to JSON file."""
        path.write_text(BenchmarkReporter.to_json(results))

    @staticmethod
    def to_markdown(results: list[BenchmarkResult]) -> str:
        """Convert results to Markdown table."""
        lines = [
            "| Benchmark | Category | Mean (ms) | Std Dev | Peak Memory (MB) | Throughput |",
            "|-----------|----------|-----------|---------|------------------|------------|",
        ]
        for r in results:
            lines.append(
                f"| {r.name} | {r.category.name} | "
                f"{r.mean_seconds * 1000:.2f} | {r.stddev_seconds * 1000:.2f} | "
                f"{r.peak_memory_mb:.2f} | {r.throughput:.0f} instr/s |"
            )
        return "\n".join(lines)
