from __future__ import annotations

from pysymex.analysis.contracts import ContractKind, VerificationResult
from pysymex.analysis.properties import PropertyKind
from pysymex.execution.executors.verified import (
    ArithmeticIssue,
    ContractIssue,
    InferredProperty,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
    VerifiedExecutor,
    check_arithmetic,
    check_contracts,
    prove_termination,
    verify,
)
from pysymex.execution.termination import TerminationStatus


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


class TestVerifiedExecutor:
    """Test suite for pysymex.execution.executors.verified.VerifiedExecutor."""

    def test_execute_function(self) -> None:
        """Test execute_function behavior."""

        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(VerifiedExecutionConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})
        assert result.function_name == "sample"


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
