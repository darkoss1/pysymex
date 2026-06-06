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

"""CLI end-to-end benchmark workloads."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from pysymex.benchmarks.suite.workload.helpers import (
    solver_outcome_counts_from_stats,
    solver_queries_from_stats,
)


_CLI_TARGET = """
def safe_ratio(x: int, y: int) -> int:
    if y == 0:
        return x + 1
    return (x + y) // y
""".strip()


def bench_cli_default_scan() -> dict[str, int]:
    """Measure the default user-facing ``pysymex scan`` subprocess path."""
    with tempfile.TemporaryDirectory(prefix="pysymex_bench_cli_") as temp_dir:
        target = Path(temp_dir) / "target.py"
        target.write_text(_CLI_TARGET, encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "pysymex",
            "scan",
            str(target),
            "--format",
            "json",
            "--max-paths",
            "64",
            "--timeout",
            "5",
            "--workers",
            "1",
            "--deterministic",
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    if completed.returncode not in {0, 1}:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"exit code {completed.returncode}"
        raise RuntimeError(f"CLI scan benchmark failed: {detail}")

    paths = 0
    solver_calls = 0
    solver_sat = 0
    solver_unsat = 0
    solver_unknown = 0
    issue_count = 0
    try:
        decoded_payload: object = json.loads(completed.stdout)
    except json.JSONDecodeError:
        decoded_payload = {}
    if isinstance(decoded_payload, dict):
        payload = cast("dict[object, object]", decoded_payload)
        issue_count = _int_field(payload, "total_issues")
        raw_results = payload.get("results")
        if isinstance(raw_results, list):
            for raw_result in cast("list[object]", raw_results):
                if not isinstance(raw_result, dict):
                    continue
                result = cast("dict[object, object]", raw_result)
                paths += _int_field(result, "paths_explored")
                raw_solver_stats = result.get("solver_stats")
                if isinstance(raw_solver_stats, dict):
                    solver_stats = cast("dict[object, object]", raw_solver_stats)
                    solver_calls += _int_field(solver_stats, "queries")
                    solver_sat += _int_field(solver_stats, "sat_results")
                    solver_unsat += _int_field(solver_stats, "unsat_results")
                    solver_unknown += _int_field(solver_stats, "unknown_results")
    return {
        "instructions": 1,
        "paths": paths,
        "solver_calls": solver_calls,
        "solver_sat": solver_sat,
        "solver_unsat": solver_unsat,
        "solver_unknown": solver_unknown,
        "issues": issue_count,
    }


def bench_scanner_default_scan() -> dict[str, int]:
    """Measure the same scan target through the in-process scanner path."""
    from pysymex.scanner.file import scan_file

    with tempfile.TemporaryDirectory(prefix="pysymex_bench_scanner_") as temp_dir:
        target = Path(temp_dir) / "target.py"
        target.write_text(_CLI_TARGET, encoding="utf-8")
        result = scan_file(
            target,
            max_paths=64,
            timeout=5.0,
            deterministic_mode=True,
            no_cache=True,
        )

    if result.error:
        raise RuntimeError(f"scanner benchmark failed: {result.error}")

    return {
        "instructions": result.code_objects,
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        "issues": len(result.issues),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }


def _int_field(payload: dict[object, object], key: str) -> int:
    """Return a non-negative integer field from decoded CLI JSON."""
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)
