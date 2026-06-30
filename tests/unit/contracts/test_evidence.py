from __future__ import annotations

import z3

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.decorators import requires
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import build_contract_evidence
from pysymex._internal.contracts.reports.summary import aggregate_runtime_outcomes
from pysymex._internal.contracts.runtime.capture import (
    RuntimeContractOutcome,
    capture_runtime_contract_outcomes,
)
from pysymex._internal.contracts.types import Contract, ContractSeverity
from pysymex.contracts import ContractKind


@requires("x > 0")
def _requires_positive(x: int) -> int:
    return x


def _first_precondition() -> Contract:
    contract = ContractRegistry.get(_requires_positive)
    assert contract is not None
    return contract.preconditions[0]


def _postcondition() -> Contract:
    return Contract(
        kind=ContractKind.ENSURES,
        predicate="result() >= 0",
        message="postcondition",
        severity=ContractSeverity.ERROR,
    )


def test_evidence_builder_preserves_obligation_context() -> None:
    clause = _first_precondition()
    condition = z3.Int("x") > 0
    constraints = [z3.Not(condition)]

    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=17,
        status=VerificationResult.VIOLATED,
        solver_status=SolverStatus.SAT,
        message="precondition may be violated",
        formula=condition,
        query_constraints=constraints,
    )

    assert evidence.status is VerificationResult.VIOLATED
    assert evidence.solver_status is SolverStatus.SAT
    assert evidence.obligation.hook is ObligationHook.CALL_SITE
    assert evidence.obligation.query_kind is QueryKind.CALL_PRECONDITION
    assert evidence.obligation.pc == 17
    assert evidence.obligation.formula is condition
    assert evidence.obligation.query_constraints == tuple(constraints)
    assert evidence.condition == "x > 0"
    assert evidence.function_name == "_requires_positive"


def test_runtime_capture_records_evidence_as_outcome_source() -> None:
    clause = _first_precondition()
    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=3,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message="call precondition verified",
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, evidence)

    assert len(outcomes) == 1
    assert outcomes[0].result is VerificationResult.VERIFIED
    assert outcomes[0].evidence is evidence
    assert outcomes[0].obligation_key[4:] == evidence.obligation.obligation_id


def test_runtime_summary_retains_selected_evidence_for_reports() -> None:
    clause = _first_precondition()
    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=3,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message="call precondition verified",
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, evidence)

    summary = aggregate_runtime_outcomes(outcomes, target_identity=id(_requires_positive))

    assert summary.evidence == [evidence]
    assert summary.verified_count == 1


def test_runtime_summary_downgrades_precision_loss_suffix_labels_on_postconditions() -> None:
    clause = _postcondition()
    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.POSTCONDITION,
        pc=3,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message="postcondition verified",
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, evidence)

    summary = aggregate_runtime_outcomes(
        outcomes,
        target_identity=999,
        degraded_passes=["symbolic_power_abstraction", "unmodeled_attribute_havoc"],
    )

    assert summary.verified_count == 0
    assert [(issue.kind, issue.result) for issue in summary.issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    downgraded = summary.evidence[0]
    assert downgraded.status is VerificationResult.UNKNOWN
    assert downgraded.solver_status is SolverStatus.UNKNOWN
    assert downgraded.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_runtime_summary_preserves_degraded_call_precondition_violations() -> None:
    clause = _first_precondition()
    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=3,
        status=VerificationResult.VIOLATED,
        solver_status=SolverStatus.SAT,
        message="call precondition violated",
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, evidence)

    summary = aggregate_runtime_outcomes(
        outcomes,
        target_identity=999,
        degraded_passes=["symbolic_power_abstraction"],
    )

    assert summary.verified_count == 0
    assert [(issue.kind, issue.result) for issue in summary.issues] == [
        (ContractKind.REQUIRES, VerificationResult.VIOLATED)
    ]
    selected = summary.evidence[0]
    assert selected.status is VerificationResult.VIOLATED
    assert selected.solver_status is SolverStatus.SAT
    assert selected.unsupported_reasons == ()


def test_runtime_summary_downgrades_degraded_postcondition_violations() -> None:
    clause = _postcondition()
    evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.POSTCONDITION,
        pc=3,
        status=VerificationResult.VIOLATED,
        solver_status=SolverStatus.SAT,
        message="postcondition violated",
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, evidence)

    summary = aggregate_runtime_outcomes(
        outcomes,
        target_identity=999,
        degraded_passes=["symbolic_power_abstraction"],
    )

    assert summary.verified_count == 0
    assert [(issue.kind, issue.result) for issue in summary.issues] == [
        (ContractKind.ENSURES, VerificationResult.UNKNOWN)
    ]
    downgraded = summary.evidence[0]
    assert downgraded.status is VerificationResult.UNKNOWN
    assert downgraded.solver_status is SolverStatus.UNKNOWN
    assert downgraded.unsupported_reasons == (UnsupportedReason.PRECISION_LOSS,)


def test_runtime_summary_selects_worst_result_across_path_local_postcondition_evidence() -> None:
    clause = _postcondition()
    x = z3.Int("x")
    verified_evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.POSTCONDITION,
        pc=7,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.UNSAT,
        message="postcondition verified on this path",
        query_constraints=[x > 0],
    )
    violated_evidence = build_contract_evidence(
        clause,
        _requires_positive,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.POSTCONDITION,
        pc=7,
        status=VerificationResult.VIOLATED,
        solver_status=SolverStatus.SAT,
        message="postcondition violated on another path",
        query_constraints=[x <= 0],
    )

    with capture_runtime_contract_outcomes() as outcomes:
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, verified_evidence)
        RuntimeContractOutcome.record_evidence(clause, _requires_positive, violated_evidence)

    summary = aggregate_runtime_outcomes(outcomes, target_identity=id(_requires_positive))

    assert summary.verified_count == 0
    assert [(issue.kind, issue.result) for issue in summary.issues] == [
        (ContractKind.ENSURES, VerificationResult.VIOLATED)
    ]
    assert summary.evidence == [violated_evidence]


def test_verified_counter_requires_evidence_not_status_inference() -> None:
    legacy_outcome = RuntimeContractOutcome(
        kind=ContractKind.REQUIRES,
        condition="x > 0",
        function_identity=1,
        function_name="legacy",
        line_number=None,
        severity=ContractSeverity.ERROR,
        result=VerificationResult.VERIFIED,
        evidence=None,
    )

    summary = aggregate_runtime_outcomes([legacy_outcome], target_identity=2)

    assert summary.issues == []
    assert summary.evidence == []
    assert summary.nested_contract_count == 1
    assert summary.verified_count == 0
