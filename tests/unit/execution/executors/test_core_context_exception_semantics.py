"""Context-manager and finally exception semantics for the symbolic executor."""

from __future__ import annotations

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_exception_targets import (
    internally_handled_context_exception_continues_to_assertion,
    propagated_context_exception_does_not_continue_to_assertion,
    propagated_context_exception_reaches_outer_handler,
    suppressed_context_exception_continues_to_assertion,
)


class ReplacingContext:
    def __enter__(self) -> int:
        return 1

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        raise ValueError("replacement")


def caught_replacement_context_exception_continues_to_assertion() -> int:
    value = 0
    try:
        with ReplacingContext():
            value = 10 // 0
    except ValueError:
        value = 1
    if value != 0:
        raise AssertionError
    return value


def uncaught_replacement_context_exception() -> int:
    with ReplacingContext():
        return 10 // 0
    return 0


def test_truthy_context_exit_continues_after_suppressed_body_exception() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=120))

    result = executor.execute_function(suppressed_context_exception_continues_to_assertion)

    assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
    assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)


def test_false_context_exit_does_not_continue_after_body_exception() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=120))

    result = executor.execute_function(propagated_context_exception_does_not_continue_to_assertion)

    assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)
    assert all(issue.kind != IssueKind.ASSERTION_ERROR for issue in result.issues)


def test_false_context_exit_reraises_into_outer_handler() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=200))

    result = executor.execute_function(propagated_context_exception_reaches_outer_handler)

    assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
    assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)


def test_context_exit_can_catch_its_own_exception_before_suppressing_body() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=240))

    result = executor.execute_function(internally_handled_context_exception_continues_to_assertion)

    assert all(
        issue.kind not in {IssueKind.DIVISION_BY_ZERO, IssueKind.UNKNOWN} for issue in result.issues
    )
    assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)


def test_context_exit_replacement_can_be_caught_by_outer_handler() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=260))

    result = executor.execute_function(caught_replacement_context_exception_continues_to_assertion)

    assert all(
        issue.kind
        not in {IssueKind.DIVISION_BY_ZERO, IssueKind.UNHANDLED_EXCEPTION, IssueKind.UNKNOWN}
        for issue in result.issues
    )
    assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)


def test_uncaught_context_exit_replacement_reports_replacement_exception() -> None:
    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=220))

    result = executor.execute_function(uncaught_replacement_context_exception)

    assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
    assert any(
        issue.kind in {IssueKind.UNHANDLED_EXCEPTION, IssueKind.VALUE_ERROR}
        and "ValueError" in issue.message
        for issue in result.issues
    )


def test_finally_return_suppresses_pending_division_issue() -> None:
    def risky(value: int) -> int:
        try:
            return 10 // value
        finally:
            return 999

    assert risky(0) == 999
    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

    result = executor.execute_function(risky, {"value": "int"})

    assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)


def test_finally_return_preserves_division_issue_raised_in_finally() -> None:
    def sneaky(value: int) -> int:
        try:
            return 999
        finally:
            return 10 // value

    executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

    result = executor.execute_function(sneaky, {"value": "int"})

    assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)
