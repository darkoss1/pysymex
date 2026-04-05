from __future__ import annotations

from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.executor_types import ExecutionConfig


def _branchy(a: int, b: int, c: int) -> int:
    out = 0
    if a > b:
        out += 1
    else:
        out += 2
    if b > c:
        out += 4
    else:
        out += 8
    return out


def test_executor_exposes_phase_telemetry() -> None:
    executor = SymbolicExecutor(
        config=ExecutionConfig(
            enable_chtd=True,
            enable_h_acceleration=False,
            max_paths=64,
            max_iterations=10000,
            enable_cross_function=False,
            enable_abstract_interpretation=False,
            enable_type_inference=False,
        )
    )

    result = executor.execute_function(_branchy, {"a": "int", "b": "int", "c": "int"})
    chtd_obj = result.solver_stats.get("chtd")
    assert isinstance(chtd_obj, dict)

    timers_obj = chtd_obj.get("phase_timers_seconds")
    counts_obj = chtd_obj.get("phase_counts")
    assert isinstance(timers_obj, dict)
    assert isinstance(counts_obj, dict)

    for key in (
        "execute_step",
        "process_execution_result",
        "path_feasibility",
        "chtd_decomposition",
        "chtd_propagation",
    ):
        timer = timers_obj.get(key)
        count = counts_obj.get(key)
        assert isinstance(timer, float)
        assert timer >= 0.0
        assert isinstance(count, int)
        assert count >= 0
