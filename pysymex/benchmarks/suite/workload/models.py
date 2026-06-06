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

"""Model-heavy benchmark workloads.

This module owns benchmarks that exercise builtin and container model dispatch
through the real symbolic executor rather than calling model helpers directly.
"""

from __future__ import annotations

from collections.abc import Callable

from pysymex.benchmarks.suite.workload.helpers import (
    coverage_count,
    solver_outcome_counts_from_stats,
    solver_queries_from_stats,
)


def _string_model_target(text: str, needle: str) -> int:
    """Target function for symbolic string model dispatch."""
    score = 0
    if text.startswith("ab"):
        score += text.count("a")
    if text.endswith("z"):
        score += len(text)
    position = text.rfind(needle)
    if position == -1:
        return score + len(needle)
    return score + position


def _container_model_target(index: int, amount: int) -> int:
    """Target function for container and builtin model dispatch."""
    values = [amount, amount + 1, amount + 2, 7]
    markers = (1, 3, 5, 7)
    total = sum(values[:3])
    if 0 <= index < len(values):
        total += values[index]
    if amount in markers:
        total += len(markers)
    if amount > 0:
        total += min(values[0], values[1])
    return total


def _run_model_workload(
    target: Callable[..., object],
    symbolic_vars: dict[str, str],
) -> dict[str, int]:
    """Execute a model-heavy source snippet and return benchmark metrics."""
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.executors import SymbolicExecutor

    config = ExecutionConfig(
        max_paths=96,
        max_depth=80,
        max_iterations=8000,
        timeout_seconds=8.0,
        deterministic_mode=True,
    )
    result = SymbolicExecutor(config).execute_function(
        target,
        symbolic_vars,
    )
    return {
        "instructions": coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        "issues": len(result.issues),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }


def bench_string_model_dispatch() -> dict[str, int]:
    """Benchmark symbolic string model dispatch through executor integration."""
    return _run_model_workload(_string_model_target, {"text": "str", "needle": "str"})


def bench_container_model_dispatch() -> dict[str, int]:
    """Benchmark list, tuple, len, sum, min, and membership model dispatch."""
    return _run_model_workload(
        _container_model_target,
        {"index": "int", "amount": "int"},
    )
