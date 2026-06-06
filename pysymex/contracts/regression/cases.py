# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Declarative contract regression cases for the public quality gate."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from pysymex.contracts.decorators import assigns, ensures, get_or_create_contract, pure, requires
from pysymex.contracts.ir.evidence import EvidenceResult
from pysymex.contracts.regression.manifest import ContractRegressionExpectation
from pysymex.contracts.reports.adapters import extract_counterexample_from_model
from pysymex.contracts.types import ContractKind, VerificationResult
from pysymex.execution.executors.verified.api import verify
from pysymex.execution.executors.verified.types import VerifiedExecutionResult


def _empty_symbolic_args() -> Mapping[str, str]:
    """Return immutable empty symbolic arguments."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ContractRegressionCase:
    """Executable contract regression case paired with a manifest expectation."""

    expectation: ContractRegressionExpectation
    target: Callable[..., object]
    symbolic_args: Mapping[str, str] = field(default_factory=_empty_symbolic_args)


@dataclass(frozen=True, slots=True)
class ContractRegressionOutcome:
    """Observed outcome for one contract regression case."""

    case: ContractRegressionCase
    result: VerifiedExecutionResult
    observed_status: VerificationResult | None
    counterexample: Mapping[str, object]

    @property
    def matches(self) -> bool:
        """Return whether the observed status satisfies the manifest expectation."""
        expected = self.case.expectation
        if self.observed_status is expected.expected_status:
            if expected.requires_counterexample:
                return bool(self.counterexample)
            return True
        return (
            expected.allowed_unknown
            and self.observed_status is VerificationResult.UNKNOWN
            and not expected.requires_counterexample
        )


@requires("x > 0")
@ensures("result() > 0")
def _native_requires_ensures_verified(x: int) -> int:
    return x


@requires("x > 0")
def _native_needs_positive(x: int) -> int:
    return x


def _native_call_site_precondition_violation(x: int) -> int:
    return _native_needs_positive(x)


@ensures("result() < 0")
def _native_postcondition_violation(x: int) -> int:
    return x


@ensures("result() == old(x) + 1")
def _native_old_scalar_postcondition(x: int) -> int:
    x = x + 1
    return x


@ensures("mystery(x) > 0")
def _native_unsupported_postcondition(x: int) -> int:
    return x


@assigns()
def _native_assigns_empty_verified(x: int) -> int:
    return x


@pure
def _native_pure_verified(x: int) -> int:
    return x


def _native_loop_invariant_unsupported(x: int) -> int:
    return x


get_or_create_contract(_native_loop_invariant_unsupported).add_loop_invariant(0, "x >= 0")


CONTRACT_REGRESSION_CASES: tuple[ContractRegressionCase, ...] = (
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_root_precondition_verified",
            family="preconditions",
            frontend="native",
            expected_status=VerificationResult.VERIFIED,
            kind=ContractKind.REQUIRES,
        ),
        target=_native_requires_ensures_verified,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_call_site_precondition_violation",
            family="call-site preconditions",
            frontend="native",
            expected_status=VerificationResult.VIOLATED,
            kind=ContractKind.REQUIRES,
            requires_counterexample=True,
        ),
        target=_native_call_site_precondition_violation,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_postcondition_violation",
            family="postconditions",
            frontend="native",
            expected_status=VerificationResult.VIOLATED,
            kind=ContractKind.ENSURES,
            requires_counterexample=True,
        ),
        target=_native_postcondition_violation,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_old_scalar_postcondition",
            family="old()",
            frontend="native",
            expected_status=VerificationResult.VERIFIED,
            kind=ContractKind.ENSURES,
        ),
        target=_native_old_scalar_postcondition,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_unsupported_postcondition",
            family="unsupported syntax",
            frontend="native",
            expected_status=VerificationResult.UNSUPPORTED,
            kind=ContractKind.ENSURES,
        ),
        target=_native_unsupported_postcondition,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_assigns_empty_verified",
            family="assigns",
            frontend="native",
            expected_status=VerificationResult.VERIFIED,
            kind=ContractKind.ASSIGNS,
        ),
        target=_native_assigns_empty_verified,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_pure_verified",
            family="pure",
            frontend="native",
            expected_status=VerificationResult.VERIFIED,
            kind=ContractKind.PURE,
        ),
        target=_native_pure_verified,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
    ContractRegressionCase(
        expectation=ContractRegressionExpectation(
            case="native_loop_invariant_unsupported",
            family="loop invariants",
            frontend="native",
            expected_status=VerificationResult.UNSUPPORTED,
            kind=ContractKind.LOOP_INVARIANT,
        ),
        target=_native_loop_invariant_unsupported,
        symbolic_args=MappingProxyType({"x": "int"}),
    ),
)


def run_contract_regression_case(case: ContractRegressionCase) -> ContractRegressionOutcome:
    """Execute one regression case through real verified execution."""
    result = verify(case.target, dict(case.symbolic_args))
    status = _observed_status(result, case.expectation.kind)
    return ContractRegressionOutcome(
        case=case,
        result=result,
        observed_status=status,
        counterexample=_observed_counterexample(result, case.expectation.kind, status),
    )


def run_contract_regression_suite(
    cases: Iterable[ContractRegressionCase] = CONTRACT_REGRESSION_CASES,
) -> tuple[ContractRegressionOutcome, ...]:
    """Execute a sequence of regression cases."""
    return tuple(run_contract_regression_case(case) for case in cases)


def assert_contract_regression_case(case: ContractRegressionCase) -> ContractRegressionOutcome:
    """Run one case and raise ``AssertionError`` if the manifest does not match."""
    outcome = run_contract_regression_case(case)
    if outcome.matches:
        return outcome
    expected = case.expectation
    raise AssertionError(
        f"{expected.case}: expected {expected.kind.name}/{expected.expected_status.name}, "
        f"observed {outcome.observed_status}"
    )


def _observed_status(
    result: VerifiedExecutionResult,
    kind: ContractKind,
) -> VerificationResult | None:
    """Select the strongest observed status for a contract kind."""
    statuses: list[VerificationResult] = []
    statuses.extend(
        evidence.status for evidence in result.contract_evidence if evidence.kind is kind
    )
    statuses.extend(issue.result for issue in result.contract_issues if issue.kind is kind)
    if not statuses:
        return None
    return max(statuses, key=_status_priority)


def _observed_counterexample(
    result: VerifiedExecutionResult,
    kind: ContractKind,
    status: VerificationResult | None,
) -> Mapping[str, object]:
    """Return the first matching counterexample for a kind/status pair."""
    if status is None:
        return MappingProxyType({})
    for issue in result.contract_issues:
        if issue.kind is kind and issue.result is status and issue.counterexample:
            return MappingProxyType(dict(issue.counterexample))
    for evidence in result.contract_evidence:
        if evidence.kind is kind and evidence.status is status:
            counterexample = _counterexample_for_evidence(evidence)
            if counterexample:
                return MappingProxyType(counterexample)
    return MappingProxyType({})


def _counterexample_for_evidence(evidence: EvidenceResult) -> dict[str, object]:
    """Return reportable counterexample data for an evidence record."""
    if evidence.counterexample:
        return dict(evidence.counterexample)
    if evidence.model is not None:
        return extract_counterexample_from_model(evidence.model)
    return {}


def _status_priority(status: VerificationResult) -> int:
    """Return priority for selecting a representative status."""
    return {
        VerificationResult.VERIFIED: 0,
        VerificationResult.UNREACHABLE: 1,
        VerificationResult.UNKNOWN: 2,
        VerificationResult.UNSUPPORTED: 3,
        VerificationResult.VIOLATED: 4,
    }[status]


__all__ = [
    "CONTRACT_REGRESSION_CASES",
    "ContractRegressionCase",
    "ContractRegressionOutcome",
    "assert_contract_regression_case",
    "run_contract_regression_case",
    "run_contract_regression_suite",
]
