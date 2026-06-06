"""Tests for symbolic executor exception-table semantics."""

from __future__ import annotations

from pysymex.analysis.detectors import IssueKind
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig
from tests.unit.execution.executors.core_executor_helpers import (
    bounded_while_post_loop_assertion,
    caught_interprocedural_division_continues_to_assertion,
    caught_interprocedural_value_error,
    caught_protocol_division_continues_to_assertion,
    caught_protocol_value_error,
    caught_runtime_error,
    caught_zero_division,
    caught_zero_division_rebinds_before_assert,
    internally_handled_context_exception_continues_to_assertion,
    nested_callee_catches_own_value_error,
    outer_handler_catches_reraised_zero_division,
    propagated_context_exception_does_not_continue_to_assertion,
    propagated_context_exception_reaches_outer_handler,
    reraise_caught_zero_division,
    suppressed_context_exception_continues_to_assertion,
    try_finally_zero_division_guarded,
    try_finally_zero_division_uncaught,
    tuple_handler_zero_division,
    uncaught_runtime_error,
    wrong_handler_zero_division,
    wrong_handler_interprocedural_value_error,
    wrong_handler_protocol_value_error,
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


class TestSymbolicExecutorExceptionSemantics:
    """Test suite for exception-table and runtime-error behavior."""

    def test_caught_zero_division_handler_suppresses_uncaught_detector_issue(self) -> None:
        """A matching CPython exception-table handler means the division is not uncaught."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(caught_zero_division, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_bare_raise_reports_caught_zero_division_that_escapes(self) -> None:
        """A handler that re-raises its active exception must not hide the failure."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(reraise_caught_zero_division, {"x": "int"})

        assert any(
            issue.kind == IssueKind.UNHANDLED_EXCEPTION and "ZeroDivisionError" in issue.message
            for issue in result.issues
        )

    def test_outer_handler_suppresses_caught_zero_division_reraise(self) -> None:
        """A propagated bare raise is no longer unhandled once an outer clause catches it."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=6, max_iterations=120))

        result = executor.execute_function(
            outer_handler_catches_reraised_zero_division, {"x": "int"}
        )

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caught_zero_division_handler_rebinding_feeds_post_try_assertion(self) -> None:
        """Caught division paths should continue through the handler with updated locals."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(
            caught_zero_division_rebinds_before_assert,
            {"x": "int"},
        )

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert all(issue.kind != IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_wrong_exception_handler_preserves_division_by_zero_issue(self) -> None:
        """A protected opcode is still reportable when the handler type does not match."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(wrong_handler_zero_division, {"x": "int"})

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_tuple_exception_handler_suppresses_division_by_zero_issue(self) -> None:
        """Tuple exception handlers should suppress caught ZeroDivisionError paths."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(tuple_handler_zero_division, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_try_finally_cleanup_does_not_suppress_uncaught_zero_division(self) -> None:
        """A finally cleanup runs before propagation but does not catch ZeroDivisionError."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(try_finally_zero_division_uncaught, {"x": "int"})

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_try_finally_guard_prevents_zero_division_issue(self) -> None:
        """A nonzero guard inside try/finally should still prevent division bugs."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(try_finally_zero_division_guarded, {"x": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_state_merging_preserves_bounded_while_post_loop_assertion(self) -> None:
        """Loop headers should not be merged in a way that hides accumulated locals."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=16, max_iterations=240))

        result = executor.execute_function(bounded_while_post_loop_assertion, {"x": "int"})

        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_uncaught_runtime_error_reports_unhandled_exception(self) -> None:
        """Explicit RuntimeError raises are reported when no handler catches them."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(uncaught_runtime_error, {"flag": "bool"})

        assert any(issue.kind == IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caught_runtime_error_suppresses_unhandled_exception(self) -> None:
        """Matching exception-table handlers suppress explicit RuntimeError reports."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(caught_runtime_error, {"flag": "bool"})

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_catches_exception_raised_by_interprocedural_call(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(caught_interprocedural_value_error)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_wrong_handler_preserves_interprocedural_exception_issue(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(wrong_handler_interprocedural_value_error)

        assert any(issue.kind == IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_callee_local_handler_catches_interprocedural_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(nested_callee_catches_own_value_error)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_continues_after_catching_interprocedural_opcode_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=100))

        result = executor.execute_function(caught_interprocedural_division_continues_to_assertion)

        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_caller_catches_exception_raised_by_truth_protocol(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=100))

        result = executor.execute_function(caught_protocol_value_error)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_continues_after_catching_truth_protocol_opcode_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=100))

        result = executor.execute_function(caught_protocol_division_continues_to_assertion)

        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_caller_wrong_handler_preserves_truth_protocol_exception_issue(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=100))

        result = executor.execute_function(wrong_handler_protocol_value_error)

        assert any(issue.kind == IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_truthy_context_exit_continues_after_suppressed_body_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=120))

        result = executor.execute_function(suppressed_context_exception_continues_to_assertion)

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_false_context_exit_does_not_continue_after_body_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=120))

        result = executor.execute_function(
            propagated_context_exception_does_not_continue_to_assertion
        )

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert all(issue.kind != IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_false_context_exit_reraises_into_outer_handler(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=200))

        result = executor.execute_function(propagated_context_exception_reaches_outer_handler)

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_context_exit_can_catch_its_own_exception_before_suppressing_body(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=240))

        result = executor.execute_function(
            internally_handled_context_exception_continues_to_assertion
        )

        assert all(
            issue.kind not in {IssueKind.DIVISION_BY_ZERO, IssueKind.UNKNOWN}
            for issue in result.issues
        )
        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_context_exit_replacement_can_be_caught_by_outer_handler(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=260))

        result = executor.execute_function(
            caught_replacement_context_exception_continues_to_assertion
        )

        assert all(
            issue.kind
            not in {IssueKind.DIVISION_BY_ZERO, IssueKind.UNHANDLED_EXCEPTION, IssueKind.UNKNOWN}
            for issue in result.issues
        )
        assert any(issue.kind == IssueKind.ASSERTION_ERROR for issue in result.issues)

    def test_uncaught_context_exit_replacement_reports_replacement_exception(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=220))

        result = executor.execute_function(uncaught_replacement_context_exception)

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)
        assert any(
            issue.kind == IssueKind.UNHANDLED_EXCEPTION and "ValueError" in issue.message
            for issue in result.issues
        )

    def test_finally_return_suppresses_pending_division_issue(self) -> None:
        def risky(value: int) -> int:
            try:
                return 10 // value
            finally:
                return 999

        assert risky(0) == 999
        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(risky, {"value": "int"})

        assert all(issue.kind != IssueKind.DIVISION_BY_ZERO for issue in result.issues)

    def test_finally_return_preserves_division_issue_raised_in_finally(self) -> None:
        def sneaky(value: int) -> int:
            try:
                return 999
            finally:
                return 10 // value

        executor = SymbolicExecutor(ExecutionConfig(max_paths=8, max_iterations=120))

        result = executor.execute_function(sneaky, {"value": "int"})

        assert any(issue.kind == IssueKind.DIVISION_BY_ZERO for issue in result.issues)
