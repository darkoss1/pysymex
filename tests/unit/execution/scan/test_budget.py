from __future__ import annotations

import types
from typing import cast

from pytest import MonkeyPatch

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.scan.budget import SCAN_TIME_LIMIT_DEGRADED_PASS, ScanTimeBudget
from pysymex._internal.execution.scan.callables import run_callable_items
from pysymex._internal.execution.scan.metrics import ExecutionMetrics


class _IssueSink:
    def handle_issue(self, issue: object) -> None:
        _ = issue


def test_scan_time_budget_clips_execution_and_solver_timeout(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("pysymex._internal.execution.scan.budget.time.perf_counter", lambda: 8.5)
    budget = ScanTimeBudget(started_at=5.0, timeout_seconds=5.0)
    config = ExecutionConfig(timeout_seconds=30.0, solver_timeout_ms=20_000)

    remaining = budget.config_with_remaining_timeout(config)

    assert remaining.timeout_seconds == 1.5
    assert remaining.solver_timeout_ms == 1500


def test_scan_time_budget_automatic_mode_preserves_config() -> None:
    config = ExecutionConfig()
    budget = ScanTimeBudget(started_at=5.0, timeout_seconds=None)

    assert budget.remaining_seconds() is None
    assert budget.expired() is False
    assert budget.config_with_remaining_timeout(config) is config


def test_run_callable_items_stops_when_file_budget_is_exhausted() -> None:
    metrics = ExecutionMetrics()
    code = _single_function_code()

    run_callable_items(
        items=[(code, None, "target")],
        seen_codes=set(),
        source_type_hints={},
        module_globals={},
        base_config=ExecutionConfig(timeout_seconds=1.0),
        executor=cast("SymbolicExecutor", object()),
        auto_tune=False,
        tracer=None,
        issue_sink=_IssueSink(),
        metrics=metrics,
        time_budget=ScanTimeBudget(started_at=0.0, timeout_seconds=0.0),
        execution_observer=None,
    )

    assert metrics.degraded_passes == [SCAN_TIME_LIMIT_DEGRADED_PASS]
    assert metrics.paths_explored == 0


def _single_function_code() -> types.CodeType:
    module_code = compile("def target():\n    return 1\n", "<scan-budget-test>", "exec")
    for constant in module_code.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("test fixture did not compile a function code object")
