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

import json
from pathlib import Path

from pysymex._internal.benchmarks.suite.reporting import BenchmarkReporter
from pysymex._internal.benchmarks.suite.types import (
    BenchmarkCategory,
    BenchmarkEvent,
    BenchmarkResult,
)


def test_reporter_outputs(tmp_path: Path) -> None:
    current = [
        BenchmarkResult(
            "b1",
            BenchmarkCategory.OPCODES,
            elapsed_seconds=1.3,
            mean_seconds=1.3,
            issue_count=2,
        ),
    ]

    as_json = BenchmarkReporter.to_json(current)
    as_md = BenchmarkReporter.to_markdown(current)
    out = tmp_path / "bench.json"
    BenchmarkReporter.to_json_file(current, out)
    markdown_out = tmp_path / "bench.md"
    BenchmarkReporter.to_file(current, markdown_out, output_format="markdown")

    assert json.loads(as_json)[0]["name"] == "b1"
    assert json.loads(as_json)[0]["issue_count"] == 2
    assert "| Benchmark |" in as_md
    assert "| b1 | OPCODES | completed | 1300.00 | 0.00 | 0.00 | 2 |" in as_md
    assert out.exists()
    assert markdown_out.read_text(encoding="utf-8").startswith("| Benchmark |")


def test_benchmark_inventory_has_clean_terminal_layout() -> None:
    """Benchmark inventory should read as a terminal section, not a cramped list."""
    rendered = BenchmarkReporter.format_inventory(["exec_core", "cli_scan"])

    assert rendered.startswith("\nBenchmark Cases\n\n")
    assert "  exec_core" in rendered
    assert "  cli_scan" in rendered
    assert "Available benchmark cases" not in rendered


def test_benchmark_progress_line_uses_plain_label() -> None:
    """Benchmark progress should use the shared plain-label style."""
    event = BenchmarkEvent(
        phase="start",
        benchmark_name="exec_core",
        category=BenchmarkCategory.OPCODES,
        completed=1,
        total=3,
    )

    assert BenchmarkReporter.progress_line(event).startswith("Benchmark: [1/3]")
