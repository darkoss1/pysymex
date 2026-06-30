from __future__ import annotations

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.cache.code.exceptions import get_exception_entries
from pysymex._internal.execution.executors.core import SymbolicExecutor


def _cached_exception_callee(value: int) -> int:
    try:
        return 10 // value
    except ZeroDivisionError:
        return 0


def _cached_exception_target(value: int) -> int:
    return _cached_exception_callee(value) + _cached_exception_callee(value + 1)


def test_interprocedural_calls_reuse_exception_entry_cache() -> None:
    get_exception_entries.cache_clear()

    config = ExecutionConfig(max_paths=16, max_iterations=500, timeout_seconds=5.0)
    result = SymbolicExecutor(config).execute_function(
        _cached_exception_target,
        symbolic_args={"value": "int"},
    )
    cache_info = get_exception_entries.cache_info()

    assert result.paths_explored > 0
    assert result.solver_stats["unknown_results"] == 0
    assert cache_info.hits >= 1
