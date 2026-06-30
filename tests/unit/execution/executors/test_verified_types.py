"""Tests for verified executor configuration and result value objects."""

from __future__ import annotations

from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex._internal.execution.executors.verified.properties.types import PropertyKind
from pysymex._internal.execution.executors.verified.types import (
    ArithmeticIssue,
    InferredProperty,
    VerifiedExecutionResult,
)
from pysymex.contracts import ContractKind, VerificationResult


class TestVerifiedExecutionConfig:
    """Test suite for pysymex._internal.config.execution.verification.VerifiedExecutionConfig."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        cfg = ExecutionVerificationConfig(max_paths=11, max_loop_iterations=3)
        assert cfg.max_paths == 11
        assert cfg.max_loop_iterations == 3


class TestContractIssue:
    """Test suite for pysymex._internal.contracts.reports.issues.ContractIssue."""

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


class TestVerifiedArithmeticIssue:
    """Test suite for pysymex._internal.execution.executors.verified.VerifiedArithmeticIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = ArithmeticIssue(kind="overflow", expression="x + 1", message="bad")
        text = issue.format()
        assert "ARITHMETIC" in text


class TestInferredProperty:
    """Test suite for pysymex._internal.execution.executors.verified.InferredProperty."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        prop = InferredProperty(
            kind=PropertyKind.MONOTONIC_INC, description="monotone", confidence=0.5
        )
        assert prop.description == "monotone"


class TestVerifiedExecutionResult:
    """Test suite for pysymex._internal.execution.executors.verified.VerifiedExecutionResult."""

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
