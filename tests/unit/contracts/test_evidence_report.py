from __future__ import annotations

from typing import cast

import z3

from pysymex.contracts.decorators import get_function_contract, requires
from pysymex.contracts.ir.evidence import SolverStatus, TheoryFeature, UnsupportedReason
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations import build_contract_evidence
from pysymex.contracts.reports.evidence import (
    EVIDENCE_REPORT_SCHEMA,
    contract_evidence_to_dict,
    not_verified_reasons_for_result,
    verified_results_evidence_report,
)
from pysymex.contracts.types import Contract, VerificationResult
from pysymex.execution.executors.verified.types import VerifiedExecutionResult


@requires("x > 0")
def _requires_positive_for_report(x: int) -> int:
    return x


def _first_clause() -> Contract:
    contract = get_function_contract(_requires_positive_for_report)
    assert contract is not None
    return contract.preconditions[0]


def test_contract_evidence_report_serializes_solver_context() -> None:
    evidence = build_contract_evidence(
        _first_clause(),
        _requires_positive_for_report,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=5,
        status=VerificationResult.UNSUPPORTED,
        solver_status=SolverStatus.UNSUPPORTED,
        message="predicate could not be lowered",
        formula=z3.Int("x") > 0,
        unsupported_reasons=(UnsupportedReason.PREDICATE_LOWERING,),
        timeout_ms=25,
        theory_profile=(TheoryFeature.INTEGER,),
    )

    data = contract_evidence_to_dict(evidence)

    assert data["status"] == "UNSUPPORTED"
    assert data["solver_status"] == "unsupported"
    assert data["kind"] == "REQUIRES"
    assert data["hook"] == "call_site"
    assert data["query_kind"] == "call_precondition"
    assert data["frontend"] == "native"
    assert data["unsupported_reasons"] == ["predicate_lowering"]
    assert data["theory_profile"] == ["integer"]


def test_verified_results_evidence_report_exposes_not_verified_reasons() -> None:
    evidence = build_contract_evidence(
        _first_clause(),
        _requires_positive_for_report,
        hook=ObligationHook.CALL_SITE,
        query_kind=QueryKind.CALL_PRECONDITION,
        pc=5,
        status=VerificationResult.UNKNOWN,
        solver_status=SolverStatus.UNKNOWN,
        message="solver returned unknown",
    )
    result = VerifiedExecutionResult(
        function_name="target",
        contracts_checked=1,
        contract_evidence=[evidence],
        degraded_passes=["solver_unknown_detector_query"],
    )

    report = verified_results_evidence_report(
        [result],
        total=0,
        duration=0.1,
        pysymex_version="test",
    )

    assert report["evidence_schema"] == EVIDENCE_REPORT_SCHEMA
    results = cast("list[object]", report["results"])
    result_data = results[0]
    assert isinstance(result_data, dict)
    summary = cast("dict[str, object]", result_data["summary"])
    assert isinstance(summary, dict)
    assert summary["not_verified_reasons"] == [
        "analysis_degraded:solver_unknown_detector_query",
        "contract_unknown",
    ]
    assert not_verified_reasons_for_result(result) == summary["not_verified_reasons"]
