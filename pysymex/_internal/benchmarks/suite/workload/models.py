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

from typing import TYPE_CHECKING

from pysymex._internal.benchmarks.suite.workload.stats_ops import WorkloadStatsOps

if TYPE_CHECKING:
    from collections.abc import Callable


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
    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.execution.executors.core import SymbolicExecutor

    config = ExecutionConfig(
        max_paths=96,
        max_depth=80,
        max_iterations=8000,
        timeout_seconds=8.0,
    )
    result = SymbolicExecutor(config).execute_function(
        target,
        symbolic_vars,
    )
    return {
        "instructions": WorkloadStatsOps.coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": WorkloadStatsOps.solver_queries_from_stats(result.solver_stats),
        "issues": len(result.issues),
        **WorkloadStatsOps.solver_outcome_counts_from_stats(result.solver_stats),
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


def bench_scalar_carrier_construction() -> dict[str, int]:
    """Benchmark isolated concrete scalar carriers over warm Z3 literals."""
    from pysymex._internal.core.types.scalars.strings import SymbolicString
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    scalar_operations = 4096
    string_operations = 1024
    checksum = 0
    for index in range(scalar_operations):
        expected = index & 31
        carrier = SymbolicValue.from_const(expected)
        if carrier.value != expected or carrier.type_tag != "int":
            msg = "scalar carrier construction lost concrete value or type"
            raise RuntimeError(msg)
        checksum += expected

    for index in range(string_operations):
        expected = str(index & 7)
        carrier = SymbolicString.from_const(expected)
        if carrier.name != repr(expected):
            msg = "string carrier construction lost its diagnostic name"
            raise RuntimeError(msg)
        exact_length = carrier.concrete_length
        if exact_length is None:
            msg = "string carrier construction lost exact length metadata"
            raise RuntimeError(msg)
        checksum += exact_length

    return {
        "instructions": scalar_operations + string_operations,
        "carrier_checksum": checksum,
    }
