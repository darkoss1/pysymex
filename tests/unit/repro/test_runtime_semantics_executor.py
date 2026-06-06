"""Symbolic executor smoke test for the runtime semantics corpus."""

from __future__ import annotations

from tests.unit.repro.runtime_semantics_helpers import all_case_functions, build_executor


def test_symbolic_executor_smoke_runs_all_realworld_cases() -> None:
    """Verify symbolic executor can execute every semantics corpus function."""
    executor = build_executor()
    completed = 0
    for function_object in all_case_functions():
        _ = executor.execute_function(function_object)
        completed += 1
    assert completed == 50
