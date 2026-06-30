"""Regression tests for executor-level result caching."""

from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_executor_helpers import simple


def initial_value_sensitive_division(x: int) -> int:
    """Trigger division by zero only when the caller constrains ``x`` to zero."""
    return 10 // x


def test_result_cache_key_includes_initial_values() -> None:
    """Different concrete initial constraints must not reuse a stale result."""
    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

    nonzero_result = executor.execute_function(
        initial_value_sensitive_division,
        {"x": "int"},
        {"x": 2},
    )
    zero_result = executor.execute_function(
        initial_value_sensitive_division,
        {"x": "int"},
        {"x": 0},
    )

    assert not nonzero_result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
    assert zero_result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)


def test_result_cache_invalidates_after_adding_detector() -> None:
    """Late detector registration changes execution semantics and must bypass stale hits."""

    class CountingDetector(Detector):
        name = "unit-result-cache-counting"
        description = "counts repeated execution after cache warmup"
        issue_kind = IssueKind.UNKNOWN
        relevant_opcodes: frozenset[str] = frozenset()

        def __init__(self) -> None:
            self.seen_opcodes: list[str] = []

        def check(
            self,
            state: VMState,
            instruction: dis.Instruction,
            _solver_check: IsSatFn,
        ) -> Issue | None:
            _ = state
            _ = _solver_check
            self.seen_opcodes.append(instruction.opname)
            return None

    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
    first = executor.execute_function(simple, {"x": "int"})
    detector = CountingDetector()
    executor.add_detector(detector)
    second = executor.execute_function(simple, {"x": "int"})

    assert first.function_name == "simple"
    assert second.function_name == "simple"
    assert detector.seen_opcodes


def test_result_cache_returns_container_isolated_results() -> None:
    """Caller mutation of one result object must not poison later cache hits."""
    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
    injected_issue = Issue(IssueKind.UNKNOWN, "caller mutation")

    first = executor.execute_function(simple, {"x": "int"})
    first.issues.append(injected_issue)
    second = executor.execute_function(simple, {"x": "int"})
    second.issues.append(injected_issue)
    third = executor.execute_function(simple, {"x": "int"})

    assert injected_issue not in second.issues[:-1]
    assert injected_issue not in third.issues
