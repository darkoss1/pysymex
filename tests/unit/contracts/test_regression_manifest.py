from __future__ import annotations

import pytest

from pysymex.contracts.regression import (
    CONTRACT_REGRESSION_CASES,
    ContractRegressionExpectation,
    assert_contract_regression_case,
    run_contract_regression_suite,
)
from pysymex.contracts.types import ContractKind, VerificationResult


def test_contract_regression_manifest_round_trips_json_shape() -> None:
    data = {
        "case": "old_scalar_postcondition",
        "frontend": "native",
        "expected_status": "VERIFIED",
        "kind": "ENSURES",
        "requires_counterexample": False,
        "allowed_unknown": False,
    }

    expectation = ContractRegressionExpectation.from_mapping(data)

    assert expectation.expected_status is VerificationResult.VERIFIED
    assert expectation.kind is ContractKind.ENSURES
    assert expectation.to_manifest() == data


def test_contract_regression_manifest_rejects_invalid_status() -> None:
    with pytest.raises(ValueError, match="expected_status"):
        ContractRegressionExpectation.from_mapping(
            {
                "case": "bad",
                "frontend": "native",
                "expected_status": "MAYBE",
                "kind": "ENSURES",
            }
        )


def test_contract_regression_cases_have_unique_manifest_names() -> None:
    names = [case.expectation.case for case in CONTRACT_REGRESSION_CASES]

    assert len(names) == len(set(names))


def test_contract_regression_cases_match_expected_statuses() -> None:
    outcomes = run_contract_regression_suite()

    assert {outcome.case.expectation.family for outcome in outcomes} >= {
        "preconditions",
        "call-site preconditions",
        "postconditions",
        "old()",
        "assigns",
        "pure",
        "loop invariants",
        "unsupported syntax",
    }
    assert all(outcome.matches for outcome in outcomes)


def test_contract_regression_case_assertion_returns_observed_outcome() -> None:
    outcome = assert_contract_regression_case(CONTRACT_REGRESSION_CASES[0])

    assert outcome.observed_status is CONTRACT_REGRESSION_CASES[0].expectation.expected_status
