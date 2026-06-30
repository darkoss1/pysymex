from __future__ import annotations

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.execution.executors.verified.api import verify
from pysymex.contracts import ContractKind, ensures, requires


def test_symbolic_power_abstraction_downgrades_verified_postcondition() -> None:
    @ensures("result() == result()")
    def target(x: int, y: int) -> int:
        return x**y

    result = verify(
        target,
        {"x": "int", "y": "int"},
        max_paths=20,
        max_iterations=200,
        timeout_seconds=5,
    )

    assert result.degraded_passes == ["symbolic_power_abstraction"]
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    assert "not counted as a definite proof" in result.contract_issues[0].message
    assert "symbolic_power_abstraction" in result.contract_issues[0].message
    evidence = result.contract_issues[0].evidence
    assert evidence is not None
    assert evidence.solver_status is SolverStatus.UNKNOWN
    assert evidence.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_symbolic_power_abstraction_downgrades_violated_postcondition() -> None:
    @ensures("result() >= 0")
    def target(x: int, y: int) -> int:
        return x**y

    result = verify(
        target,
        {"x": "int", "y": "int"},
        max_paths=20,
        max_iterations=200,
        timeout_seconds=5,
    )

    assert result.degraded_passes == ["symbolic_power_abstraction"]
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    assert "not counted as a definite violation" in result.contract_issues[0].message
    assert "symbolic_power_abstraction" in result.contract_issues[0].message
    evidence = result.contract_issues[0].evidence
    assert evidence is not None
    assert evidence.solver_status is SolverStatus.UNKNOWN
    assert evidence.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_symbolic_shift_abstraction_downgrades_verified_postcondition() -> None:
    @ensures("result() == result()")
    def target(x: int, y: int) -> int:
        return x << y

    result = verify(
        target,
        {"x": "int", "y": "int"},
        max_paths=20,
        max_iterations=200,
        timeout_seconds=5,
    )

    assert result.degraded_passes == ["symbolic_shift_abstraction"]
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    evidence = result.contract_issues[0].evidence
    assert evidence is not None
    assert evidence.solver_status is SolverStatus.UNKNOWN
    assert evidence.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_unmodeled_attribute_havoc_downgrades_verified_postcondition() -> None:
    class Factory:
        def __call__(self) -> object:
            return object()

    factory = Factory()

    @ensures("result() == result()")
    def target(x: int, make: Factory = factory) -> object:
        return make().field  # type: ignore[attr-defined]

    result = verify(
        target,
        {"x": "int"},
        max_paths=20,
        max_iterations=200,
        timeout_seconds=5,
    )

    assert result.degraded_passes == [
        "unmodeled_call_abstraction",
        "unmodeled_attribute_havoc",
    ]
    assert result.contracts_checked == 1
    assert result.contracts_verified == 0
    assert result.contracts_violated == 0
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    evidence = result.contract_issues[0].evidence
    assert evidence is not None
    assert evidence.solver_status is SolverStatus.UNKNOWN
    assert evidence.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_later_symbolic_abstraction_keeps_prior_call_precondition_violation() -> None:
    @requires("amount > 0")
    def child(amount: int) -> int:
        return amount

    @ensures("result() == result()")
    def target(x: int, y: int) -> int:
        child(x - 10)
        return x**y

    result = verify(
        target,
        {"x": "int", "y": "int"},
        max_paths=20,
        max_iterations=200,
        timeout_seconds=5,
    )

    assert result.degraded_passes == ["symbolic_power_abstraction"]
    assert result.contracts_checked == 2
    assert result.contracts_verified == 0
    assert result.contracts_violated == 1
    assert [(issue.kind, issue.result) for issue in result.contract_issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED),
        (ContractKind.ENSURES, VerificationResult.UNKNOWN),
    ]
    precondition_evidence = result.contract_issues[0].evidence
    assert precondition_evidence is not None
    assert precondition_evidence.solver_status is SolverStatus.SAT
    assert precondition_evidence.unsupported_reasons == ()
    postcondition_evidence = result.contract_issues[1].evidence
    assert postcondition_evidence is not None
    assert postcondition_evidence.solver_status is SolverStatus.UNKNOWN
    assert postcondition_evidence.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)
