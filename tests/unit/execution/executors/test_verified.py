from __future__ import annotations

from unittest.mock import patch

from pysymex.contracts import ContractKind, VerificationResult
from pysymex.contracts.decorator_registry import get_or_create_contract
from pysymex.contracts.decorators import assigns, assumes, ensures, pure, requires
from pysymex.analysis.static.properties import PropertyKind
from pysymex.execution.executors.verified.api import (
    check_arithmetic,
    check_contracts,
    prove_termination,
    verify,
)
from pysymex.execution.executors.verified.executor import VerifiedExecutor
from pysymex.execution.executors.verified.types import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
)
from pysymex.execution.termination import TerminationStatus
from pysymex.execution.results.result import ExecutionResult


class TestVerifiedExecutionConfig:
    """Test suite for pysymex.execution.executors.verified.VerifiedExecutionConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = VerifiedExecutionConfig(max_paths=11, check_termination=True)
        assert cfg.max_paths == 11
        assert cfg.check_termination is True


class TestContractIssue:
    """Test suite for pysymex.execution.executors.verified.ContractIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = ContractIssue(
            kind=ContractKind.ENSURES,
            condition="x > 0",
            message="failed",
            result=VerificationResult.VIOLATED,
        )
        text = issue.format()
        assert "ENSURES" in text


class TestArithmeticIssue:
    """Test suite for pysymex.execution.executors.verified.ArithmeticIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = ArithmeticIssue(kind="overflow", expression="x + 1", message="bad")
        text = issue.format()
        assert "ARITHMETIC" in text


class TestInferredProperty:
    """Test suite for pysymex.execution.executors.verified.InferredProperty."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        prop = InferredProperty(
            kind=PropertyKind.MONOTONIC_INC, description="monotone", confidence=0.5
        )
        assert prop.description == "monotone"


class TestVerifiedExecutionResult:
    """Test suite for pysymex.execution.executors.verified.VerifiedExecutionResult."""

    def test_is_verified(self) -> None:
        """Test is_verified behavior."""
        result = VerifiedExecutionResult()
        assert result.is_verified is True

    def test_has_issues(self) -> None:
        """Test has_issues behavior."""
        result = VerifiedExecutionResult(
            contract_issues=[ContractIssue(kind=ContractKind.REQUIRES, condition="x", message="m")]
        )
        assert result.has_issues is True

    def test_format_summary(self) -> None:
        """Test format_summary behavior."""
        result = VerifiedExecutionResult(function_name="f", paths_explored=1, paths_completed=1)
        summary = result.format_summary()
        assert "Verified Execution: f" in summary

    def test_degraded_result_is_not_verified(self) -> None:
        result = VerifiedExecutionResult(degraded_passes=["solver_unknown_detector_query"])

        assert result.is_verified is False
        assert "Analysis degraded: solver_unknown_detector_query" in result.format_summary()


class TestVerifiedExecutor:
    """Test suite for pysymex.execution.executors.verified.VerifiedExecutor."""

    def test_execute_function(self) -> None:
        """Test execute_function behavior."""

        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})
        assert result.function_name == "sample"

    def test_execute_function_preserves_core_degradation(self) -> None:
        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        with patch(
            "pysymex.execution.executors.core.SymbolicExecutor.execute_function",
            return_value=ExecutionResult(degraded_passes=["solver_unknown_detector_query"]),
        ):
            result = executor.execute_function(sample, {"x": "int"})

        assert result.degraded_passes == ["solver_unknown_detector_query"]
        assert result.is_verified is False

    def test_unsupported_contract_is_not_counted_as_violation(self) -> None:
        @requires("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contracts_verified == 0
        assert result.contracts_violated == 0
        assert len(result.contract_issues) == 1
        assert result.contract_issues[0].result is VerificationResult.UNSUPPORTED

    def test_postcondition_outcomes_are_counted_per_clause(self) -> None:
        @ensures("mystery(x) > 0")
        @ensures("result() > 10")
        def sample(x: int) -> int:
            return 0

        result = VerifiedExecutor().execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 2
        assert result.contracts_verified == 0
        assert result.contracts_violated == 1
        assert [issue.result for issue in result.contract_issues] == [
            VerificationResult.VIOLATED,
            VerificationResult.UNSUPPORTED,
        ]

    def test_uncontracted_nested_function_does_not_break_postcondition_frame(self) -> None:
        @ensures("result() >= 0")
        def sample(x: int) -> int:
            def helper(value: int) -> int:
                return value + 1

            return helper(x * x)

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=80))
        result = executor.execute_function(sample, {"x": "int"})

        assert "core_symbolic_execution_failed" not in result.degraded_passes
        assert result.contracts_checked == 1

    def test_unsupported_assumption_is_reported_as_assumption(self) -> None:
        @assumes("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})

        assert len(result.contract_issues) == 1
        assert result.contract_issues[0].kind is ContractKind.ASSUMES
        assert result.contract_issues[0].result is VerificationResult.UNSUPPORTED

    def test_interprocedural_precondition_violation_is_classified_and_counted(self) -> None:
        @requires("x > 0")
        def needs_positive(x: int) -> int:
            return x

        def caller(x: int) -> int:
            return needs_positive(x)

        result = VerifiedExecutor().execute_function(caller, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contracts_violated == 1
        assert result.contract_issues[0].kind is ContractKind.REQUIRES
        assert result.contract_issues[0].result is VerificationResult.VIOLATED

    def test_docstring_contract_tag_is_not_counted_without_execution_semantics(self) -> None:
        def sample(x: int) -> int:
            """:requires: x > 0"""
            return x

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 0
        assert result.contracts_verified == 0

    def test_disabled_postcondition_is_not_executed_or_counted(self) -> None:
        @ensures("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        config = VerifiedExecutionConfig(max_paths=4, max_iterations=40, check_postconditions=False)
        result = VerifiedExecutor(config).execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 0
        assert result.contract_issues == []

    def test_disabled_precondition_preserves_enabled_postcondition_check(self) -> None:
        @requires("mystery(x) > 0")
        @ensures("result() == x")
        def sample(x: int) -> int:
            return x

        config = VerifiedExecutionConfig(max_paths=4, max_iterations=40, check_preconditions=False)
        result = VerifiedExecutor(config).execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contracts_verified == 1
        assert result.contract_issues == []

    def test_empty_frame_condition_without_writes_is_verified(self) -> None:
        @assigns()
        def sample(x: int) -> int:
            return x

        result = VerifiedExecutor().execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contracts_verified == 1
        assert result.contract_issues == []
        assert result.is_verified is True

    def test_purity_without_writes_is_verified(self) -> None:
        @pure
        def sample(x: int) -> int:
            return x

        result = VerifiedExecutor().execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contracts_verified == 1
        assert result.contract_issues == []

    def test_unenforced_loop_invariant_is_reported_as_unsupported(self) -> None:
        def sample(x: int) -> int:
            return x

        contract = get_or_create_contract(sample)
        contract.add_loop_invariant(0, "x >= 0")

        result = VerifiedExecutor().execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contract_issues[0].kind is ContractKind.LOOP_INVARIANT
        assert result.contract_issues[0].result is VerificationResult.UNSUPPORTED


def test_verify() -> None:
    """Test verify behavior."""

    def sample(x: int) -> int:
        return x + 1

    result = verify(sample, {"x": "int"}, max_paths=3, max_iterations=30)
    assert result.function_name == "sample"


def test_check_contracts() -> None:
    """Test check_contracts behavior."""

    def sample(x: int) -> int:
        return x

    issues = check_contracts(sample, {"x": "int"})
    assert isinstance(issues, list)


def test_check_arithmetic() -> None:
    """Test check_arithmetic behavior."""

    def sample(x: int) -> int:
        return x + 1

    issues = check_arithmetic(sample, {"x": "int"})
    assert isinstance(issues, list)


def test_prove_termination() -> None:
    """Test prove_termination behavior."""

    def sample(x: int) -> int:
        return x + 1

    proof = prove_termination(sample, {"x": "int"})
    assert proof.status is TerminationStatus.UNKNOWN
