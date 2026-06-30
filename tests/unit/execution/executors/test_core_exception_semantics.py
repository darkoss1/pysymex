"""Tests for symbolic executor exception-table semantics."""

from __future__ import annotations

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_exception_targets import (
    bounded_while_post_loop_assertion,
    caught_interprocedural_division_continues_to_assertion,
    caught_interprocedural_value_error,
    caught_protocol_division_continues_to_assertion,
    caught_protocol_value_error,
    caught_runtime_error,
    caught_zero_division,
    caught_zero_division_rebinds_before_assert,
    nested_callee_catches_own_value_error,
    outer_handler_catches_reraised_zero_division,
    reraise_caught_zero_division,
    try_finally_zero_division_guarded,
    try_finally_zero_division_uncaught,
    tuple_handler_zero_division,
    uncaught_runtime_error,
    wrong_handler_interprocedural_value_error,
    wrong_handler_protocol_value_error,
    wrong_handler_zero_division,
)


def later_handler_catches_lookup_error(x: int) -> int:
    try:
        if x > 0:
            raise LookupError("bad")
    except ValueError:
        return 1
    except LookupError:
        return 0
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

        zero_division_reraises = [
            issue
            for issue in result.issues
            if issue.kind == IssueKind.UNHANDLED_EXCEPTION and "ZeroDivisionError" in issue.message
        ]
        assert len(zero_division_reraises) == 1

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

        assert any(
            issue.kind == IssueKind.UNHANDLED_EXCEPTION and "RuntimeError" in issue.message
            for issue in result.issues
        )

    def test_caught_runtime_error_suppresses_unhandled_exception(self) -> None:
        """Matching exception-table handlers suppress explicit RuntimeError reports."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))

        result = executor.execute_function(caught_runtime_error, {"flag": "bool"})

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_later_handler_suppresses_unmatched_prior_handler_branch(self) -> None:
        """A concrete false CHECK_EXC_MATCH must not leave the later true match reraising."""
        assert later_handler_catches_lookup_error(-1) == 0
        assert later_handler_catches_lookup_error(1) == 0
        executor = SymbolicExecutor(ExecutionConfig(max_paths=6, max_iterations=120))

        result = executor.execute_function(later_handler_catches_lookup_error, {"x": "int"})

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_catches_exception_raised_by_interprocedural_call(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(caught_interprocedural_value_error)

        assert all(issue.kind != IssueKind.UNHANDLED_EXCEPTION for issue in result.issues)

    def test_caller_wrong_handler_preserves_interprocedural_exception_issue(self) -> None:
        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=80))

        result = executor.execute_function(wrong_handler_interprocedural_value_error)

        assert any(
            issue.kind == IssueKind.VALUE_ERROR and "boom" in issue.message
            for issue in result.issues
        )

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

        assert any(
            issue.kind == IssueKind.VALUE_ERROR and "truth" in issue.message
            for issue in result.issues
        )
