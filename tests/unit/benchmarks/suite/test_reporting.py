# pysymex: Python Symbolic Execution & Formal Verification
from __future__ import annotations

import json
from pathlib import Path

from pysymex.benchmarks.suite.reporting import BenchmarkReporter
from pysymex.benchmarks.suite.types import BenchmarkCategory, BenchmarkResult


def test_reporter_outputs(tmp_path: Path) -> None:
    current = [
        BenchmarkResult("b1", BenchmarkCategory.OPCODES, elapsed_seconds=1.3, mean_seconds=1.3),
    ]

    as_json = BenchmarkReporter.to_json(current)
    as_md = BenchmarkReporter.to_markdown(current)
    out = tmp_path / "bench.json"
    BenchmarkReporter.to_json_file(current, out)

    assert json.loads(as_json)[0]["name"] == "b1"
    assert "| Benchmark |" in as_md
    assert out.exists()
