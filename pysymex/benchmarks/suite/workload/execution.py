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

"""Execution-focused built-in benchmark workloads."""

from __future__ import annotations

from pysymex.benchmarks.suite.workload.helpers import (
    coverage_count,
    solver_outcome_counts_from_stats,
    solver_queries_from_stats,
)
from pysymex.logger import get_logger

logger = get_logger(__name__)

_PATH_EXPLOSION_SOURCE = """
def target(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int) -> int:
    score = 0
    if a > 0:
        score += 1
    else:
        score -= 1
    if b > 0:
        score += 2
    else:
        score -= 2
    if c > 0:
        score += 3
    else:
        score -= 3
    if d > 0:
        score += 4
    else:
        score -= 4
    if e > 0:
        score += 5
    else:
        score -= 5
    if f > 0:
        score += 6
    else:
        score -= 6
    if g > 0:
        score += 7
    else:
        score -= 7
    if h > 0:
        score += 8
    else:
        score -= 8
    return score
"""


def bench_bytecode_line_mapping_cache_hits() -> dict[str, int]:
    """Benchmark: cached PC-to-line metadata during repeated bytecode preparation."""
    from types import FunctionType

    from pysymex.core.cache.code_objects import get_instructions
    from pysymex.execution.engine import build_line_mapping
    from pysymex.execution.engine import clear_line_mapping_cache, line_mapping_cache_stats
    from pysymex.execution.session.state import ExecutionSession

    source_lines = ["def target(x):", "    total = 0"]
    for index in range(64):
        source_lines.append(f"    if x == {index}:")
        source_lines.append(f"        total += {index}")
    source_lines.append("    return total")

    namespace: dict[str, object] = {}
    exec(compile("\n".join(source_lines), "<bench_line_mapping_cache>", "exec"), namespace)
    target = namespace["target"]
    if not isinstance(target, FunctionType):
        msg = "bytecode line-mapping benchmark target is not a function"
        raise TypeError(msg)

    code = target.__code__
    cached_instructions = get_instructions(code)
    sessions = 256
    clear_line_mapping_cache()
    for _ in range(sessions):
        session = ExecutionSession()
        session.instructions = list(cached_instructions)
        build_line_mapping(session=session, code=code)

    cache_stats = line_mapping_cache_stats()
    return {
        "instructions": len(cached_instructions) * sessions,
        "paths": sessions,
        "solver_calls": 0,
        "cache_hits": cache_stats["hits"],
    }


def bench_bytecode_exception_entries_cache_hits() -> dict[str, int]:
    """Benchmark: cached CPython exception-table metadata extraction."""
    from types import FunctionType

    from pysymex.core.cache.code_objects import get_exception_entries

    source = """
def target(x):
    total = 0
    for index in range(16):
        try:
            total += 100 // (x - index)
        except ZeroDivisionError:
            total += index
    return total
"""
    namespace: dict[str, object] = {}
    exec(compile(source, "<bench_exception_entries_cache>", "exec"), namespace)
    target = namespace["target"]
    if not isinstance(target, FunctionType):
        msg = "bytecode exception-entry benchmark target is not a function"
        raise TypeError(msg)

    code = target.__code__
    attempts = 512
    get_exception_entries.cache_clear()
    for _ in range(attempts):
        entries = get_exception_entries(code)
        if not entries:
            msg = "exception-entry cache benchmark expected exception metadata"
            raise AssertionError(msg)

    cache_info = get_exception_entries.cache_info()
    return {
        "instructions": attempts,
        "paths": 1,
        "solver_calls": 0,
        "cache_hits": cache_info.hits,
    }


def bench_executor_core_function() -> dict[str, int]:
    """Benchmark: SymbolicExecutor core on a compiled function workload."""
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.executors import SymbolicExecutor

    source = """
def target(x, y):
    z = x + y
    if z > 10:
        return z // (y - x)
    if x < 0:
        return x * 2
    return z + 1
"""
    code = compile(source, "<bench_executor_core_function>", "exec")
    config = ExecutionConfig(
        max_paths=64,
        max_depth=64,
        max_iterations=4000,
        timeout_seconds=10.0,
        deterministic_mode=True,
    )
    result = SymbolicExecutor(config).execute_code(
        code,
        symbolic_vars={"x": "int", "y": "int"},
    )
    return {
        "instructions": coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }


def bench_executor_core_branching() -> dict[str, int]:
    """Benchmark: SymbolicExecutor core on a branch-heavy compiled workload."""
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.executors import SymbolicExecutor

    source = """
def target(a, b, c):
    score = a + b - c
    if a > 0:
        score += 3
    else:
        score -= 2
    if b % 2 == 0:
        score *= 2
    else:
        score -= 5
    if c == 0:
        return score + 7
    if score > 20:
        return score // c
    return score + c
"""
    code = compile(source, "<bench_executor_core_branching>", "exec")
    config = ExecutionConfig(
        max_paths=128,
        max_depth=64,
        max_iterations=8000,
        timeout_seconds=10.0,
        deterministic_mode=True,
    )
    result = SymbolicExecutor(config).execute_code(
        code,
        symbolic_vars={"a": "int", "b": "int", "c": "int"},
    )
    return {
        "instructions": coverage_count(result.coverage),
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }


def bench_executor_path_explosion_native_cap() -> dict[str, int]:
    """Benchmark: capped branch explosion through the default native runtime queue."""
    from pysymex.execution.frontier import FrontierRuntimeMode

    return _bench_executor_path_explosion_cap(
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )


def bench_state_forking() -> dict[str, int]:
    """Benchmark: VMState CoW fork performance."""
    try:
        from pysymex.core.state.record import VMState
    except ImportError:
        logger.warning("VMState unavailable for benchmark workload", exc_info=True)
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    state = VMState()
    for i in range(50):
        v = z3.Int(f"var_{i}")
        state.local_vars[f"var_{i}"] = v
        state.add_constraint(v >= 0)

    retained_states: list[object] = []
    current = state
    forks = 0
    for i in range(1000):
        current = current.fork()
        current.local_vars[f"var_depth_{i}"] = i
        retained_states.append(current)
        forks += 1
    return {"instructions": forks, "paths": forks, "solver_calls": 0}


def _bench_executor_path_explosion_cap(
    *,
    frontier_runtime_mode: object,
) -> dict[str, int]:
    """Run the shared capped path-explosion workload under one frontier mode."""
    from pysymex.execution.config.settings import ExecutionConfig
    from pysymex.execution.executors import SymbolicExecutor
    from pysymex.execution.frontier import FrontierRuntimeMode

    if not isinstance(frontier_runtime_mode, FrontierRuntimeMode):
        msg = f"unexpected frontier runtime mode: {frontier_runtime_mode!r}"
        raise TypeError(msg)

    namespace: dict[str, object] = {}
    exec(compile(_PATH_EXPLOSION_SOURCE, "<bench_path_explosion_cap>", "exec"), namespace)
    target = namespace["target"]
    if not callable(target):
        msg = "path-explosion benchmark target is not callable"
        raise TypeError(msg)

    config = ExecutionConfig(
        max_paths=64,
        max_depth=256,
        max_iterations=50000,
        timeout_seconds=30.0,
        enable_cross_function=False,
        enable_type_inference=False,
        enable_fp_filtering=False,
        deterministic_mode=False,
        random_seed=7,
        frontier_runtime_mode=frontier_runtime_mode,
    )
    result = SymbolicExecutor(config).execute_function(
        target,
        symbolic_args={name: "int" for name in "abcdefgh"},
    )
    return {
        "instructions": result.paths_completed,
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }
