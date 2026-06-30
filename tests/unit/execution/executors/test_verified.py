from __future__ import annotations

from unittest.mock import patch

import pytest

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.decorators import assigns, assumes, ensures, pure, requires
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.executors.verified.api import (
    check_arithmetic,
    check_contracts,
    prove_termination,
    verify,
)
from pysymex._internal.execution.executors.verified.executor.projection.arithmetic import (
    is_projectable_arithmetic_issue,
    project_arithmetic_issue,
)
from pysymex._internal.execution.executors.verified.executor.projection.contracts import (
    is_adjacent_contract_unknown,
    project_unknown_contract_issue,
)
from pysymex._internal.execution.executors.verified.executor.runner import VerifiedExecutor
from pysymex._internal.execution.executors.verified.executor.runner import (
    VerifiedExecutor as VerifiedExecutorOwner,
)
from pysymex._internal.execution.executors.verified.properties.types import (
    ProofStatus,
    PropertyKind,
)
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.termination import TerminationStatus
from pysymex.contracts import ContractKind, VerificationResult


class TestVerifiedExecutor:
    """Test suite for pysymex._internal.execution.executors.verified.VerifiedExecutor."""

    def test_public_export_points_to_direct_owner(self) -> None:
        """The package import surface stays wired to the verified runner owner."""
        assert VerifiedExecutor is VerifiedExecutorOwner

    def test_arithmetic_projection_owner_converts_core_detector_issue(self) -> None:
        """Arithmetic issue projection stays owned outside core result assembly."""
        issue = Issue(
            kind=IssueKind.OVERFLOW,
            message="bounded integer overflow is feasible",
            model={"left": 1},
            line_number=12,
        )

        projected = project_arithmetic_issue(issue)

        assert is_projectable_arithmetic_issue(issue) is True
        assert projected.kind == "overflow"
        assert projected.expression == issue.message
        assert projected.counterexample == {"left": 1}
        assert projected.line_number == 12

    def test_unknown_contract_projection_owner_preserves_unsupported_result(self) -> None:
        """Contract-adjacent UNKNOWN projection preserves unsupported classification."""
        issue = Issue(
            kind=IssueKind.UNKNOWN,
            message="precondition could not be modeled",
            line_number=9,
            function_name="sample",
        )

        projected = project_unknown_contract_issue(issue)

        assert is_adjacent_contract_unknown(issue) is True
        assert projected is not None
        assert projected.kind is ContractKind.REQUIRES
        assert projected.result is VerificationResult.UNSUPPORTED
        assert projected.line_number == 9
        assert projected.function_name == "sample"

    def test_nested_unknown_contract_projection_remains_runtime_owned(self) -> None:
        """Callee-owned runtime contract messages are left to runtime aggregation."""
        issue = Issue(
            kind=IssueKind.UNKNOWN,
            message="precondition of callee could not be modeled",
        )

        assert project_unknown_contract_issue(issue) is None

    def test_execute_function(self) -> None:
        """Test execute_function behavior."""

        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})
        assert result.function_name == "sample"

    def test_execute_function_preserves_core_degradation(self) -> None:
        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
        with patch(
            "pysymex._internal.execution.executors.core.SymbolicExecutor.execute_function",
            return_value=ExecutionResult(degraded_passes=["solver_unknown_detector_query"]),
        ):
            result = executor.execute_function(sample, {"x": "int"})

        assert result.degraded_passes == ["solver_unknown_detector_query"]
        assert result.is_verified is False

    def test_execute_function_propagates_inner_symbolic_execution_failure(self) -> None:
        def sample(x: int) -> int:
            return x + 1

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
        with (
            patch(
                "pysymex._internal.execution.executors.core.SymbolicExecutor.execute_function",
                side_effect=RuntimeError("symbolic core failed"),
            ),
            pytest.raises(RuntimeError, match="symbolic core failed"),
        ):
            executor.execute_function(sample, {"x": "int"})

    def test_unsupported_contract_is_not_counted_as_violation(self) -> None:
        @requires("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
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

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=80))
        result = executor.execute_function(sample, {"x": "int"})

        assert "core_symbolic_execution_failed" not in result.degraded_passes
        assert result.contracts_checked == 1

    def test_unsupported_assumption_is_reported_as_assumption(self) -> None:
        @assumes("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
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

        executor = VerifiedExecutor(ExecutionVerificationConfig(max_paths=4, max_iterations=40))
        result = executor.execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 0
        assert result.contracts_verified == 0

    def test_disabled_postcondition_is_not_executed_or_counted(self) -> None:
        @ensures("mystery(x) > 0")
        def sample(x: int) -> int:
            return x

        config = ExecutionVerificationConfig(
            max_paths=4, max_iterations=40, check_postconditions=False
        )
        result = VerifiedExecutor(config).execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 0
        assert result.contract_issues == []

    def test_disabled_precondition_preserves_enabled_postcondition_check(self) -> None:
        @requires("mystery(x) > 0")
        @ensures("result() == x")
        def sample(x: int) -> int:
            return x

        config = ExecutionVerificationConfig(
            max_paths=4, max_iterations=40, check_preconditions=False
        )
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

        contract = ContractRegistry.get_or_create(sample)
        contract.add_loop_invariant(0, "x >= 0")

        result = VerifiedExecutor().execute_function(sample, {"x": "int"})

        assert result.contracts_checked == 1
        assert result.contract_issues[0].kind is ContractKind.LOOP_INVARIANT
        assert result.contract_issues[0].result is VerificationResult.UNSUPPORTED

    def test_infer_properties_records_bounded_execution_when_enabled(self) -> None:
        def sample(x: int) -> int:
            return x + 1

        config = ExecutionVerificationConfig(
            infer_properties=True,
            max_paths=3,
            max_iterations=30,
        )
        result = VerifiedExecutor(config).execute_function(sample, {"x": "int"})

        assert len(result.inferred_properties) == 1
        inferred = result.inferred_properties[0]
        assert inferred.kind is PropertyKind.BOUNDED
        assert inferred.confidence == 1.0
        assert inferred.proof is not None
        assert inferred.proof.status is ProofStatus.PROVEN

    def test_infer_properties_records_unknown_for_structural_infinite_loop(self) -> None:
        def spin(x: int) -> int:
            while True:
                x += 1
            return x

        config = ExecutionVerificationConfig(
            infer_properties=True,
            max_paths=2,
            max_iterations=20,
        )
        result = VerifiedExecutor(config).execute_function(spin, {"x": "int"})

        assert result.degraded_passes == []
        assert any(issue.kind is IssueKind.INFINITE_LOOP for issue in result.issues)
        assert len(result.inferred_properties) == 1
        inferred = result.inferred_properties[0]
        assert inferred.kind is PropertyKind.BOUNDED
        assert inferred.confidence == 0.0
        assert inferred.proof is not None
        assert inferred.proof.status is ProofStatus.UNKNOWN


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


def test_prove_termination_reports_bounded_completed_execution() -> None:
    """Completed bounded execution is reported as termination evidence."""

    def sample(x: int) -> int:
        return x + 1

    proof = prove_termination(sample, {"x": "int"}, max_paths=3, max_iterations=30)

    assert proof.status is TerminationStatus.TERMINATES
    assert "completed all accounted paths" in proof.message


def test_prove_termination_reports_unknown_without_completed_paths() -> None:
    """Structural infinite-loop evidence does not become a termination proof."""

    def spin(x: int) -> int:
        while True:
            x += 1
        return x

    proof = prove_termination(spin, {"x": "int"}, max_paths=2, max_iterations=20)

    assert proof.status is TerminationStatus.UNKNOWN
    assert proof.message == "Termination inconclusive: no symbolic paths completed"
