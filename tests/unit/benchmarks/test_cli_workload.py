from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from pysymex.benchmarks.suite.workload.cli import (
    bench_cli_default_scan,
    bench_scanner_default_scan,
)
from pysymex.scanner.types import ScanResult


def test_cli_default_scan_workload_collects_json_metrics() -> None:
    completed = subprocess.CompletedProcess(
        args=["python", "-m", "pysymex"],
        returncode=0,
        stdout=json.dumps(
            {
                "total_issues": 0,
                "results": [
                    {
                        "paths_explored": 3,
                        "solver_stats": {
                            "queries": 7,
                            "sat_results": 5,
                            "unsat_results": 2,
                            "unknown_results": 0,
                        },
                    }
                ],
            }
        ),
        stderr="",
    )

    with patch("pysymex.benchmarks.suite.workload.cli.subprocess.run", return_value=completed):
        result = bench_cli_default_scan()

    assert result["paths"] == 3
    assert result["solver_calls"] == 7
    assert result["solver_sat"] == 5
    assert result["solver_unsat"] == 2
    assert result["solver_unknown"] == 0
    assert result["issues"] == 0


def test_cli_default_scan_workload_fails_on_bad_process_status() -> None:
    completed = subprocess.CompletedProcess(
        args=["python", "-m", "pysymex"],
        returncode=2,
        stdout="",
        stderr="bad args",
    )

    with patch("pysymex.benchmarks.suite.workload.cli.subprocess.run", return_value=completed):
        try:
            bench_cli_default_scan()
        except RuntimeError as exc:
            assert "bad args" in str(exc)
        else:
            raise AssertionError("expected CLI benchmark failure")


def test_scanner_default_scan_workload_collects_scan_metrics() -> None:
    scan_result = ScanResult(
        file_path="target.py",
        timestamp="2026-01-01T00:00:00",
        issues=[{"kind": "DIVISION_BY_ZERO"}],
        code_objects=1,
        paths_explored=2,
        solver_stats={
            "queries": 4,
            "sat_results": 3,
            "unsat_results": 1,
            "unknown_results": 0,
        },
    )

    with patch("pysymex.scanner.file.scan_file", return_value=scan_result):
        result = bench_scanner_default_scan()

    assert result["instructions"] == 1
    assert result["paths"] == 2
    assert result["solver_calls"] == 4
    assert result["solver_sat"] == 3
    assert result["solver_unsat"] == 1
    assert result["solver_unknown"] == 0
    assert result["issues"] == 1
