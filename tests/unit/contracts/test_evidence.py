from __future__ import annotations

import z3

from pysymex.contracts.decorators import get_function_contract, requires
from pysymex.contracts.ir.evidence import SolverStatus
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations import build_contract_evidence
from pysymex.contracts.runtime.capture import (
    RuntimeContractOutcome,
    capture_runtime_contract_outcomes,
    record_runtime_contract_evidence,
)
from pysymex.contracts.types import Contract, ContractKind, Severity, VerificationResult
from pysymex.contracts.reports.summary import aggregate_runtime_contract_outcomes


@requires("x > 0")
def _requires_positive(x: int) -> int:
    return x


def _first_precondition() -> Contract:
    contract = get_function_contract(_requires_positive)
    assert contract is not None
    return contract.preconditions[0]


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
        record_runtime_contract_evidence(clause, _requires_positive, evidence)

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
        record_runtime_contract_evidence(clause, _requires_positive, evidence)

    summary = aggregate_runtime_contract_outcomes(outcomes, target_identity=999)

    assert summary.evidence == [evidence]
    assert summary.verified_count == 1


def test_verified_counter_requires_evidence_not_status_inference() -> None:
    legacy_outcome = RuntimeContractOutcome(
        kind=ContractKind.REQUIRES,
        condition="x > 0",
        function_identity=1,
        function_name="legacy",
        line_number=None,
        severity=Severity.ERROR,
        result=VerificationResult.VERIFIED,
        evidence=None,
    )

    summary = aggregate_runtime_contract_outcomes([legacy_outcome], target_identity=2)

    assert summary.issues == []
    assert summary.evidence == []
    assert summary.nested_contract_count == 1
    assert summary.verified_count == 0
