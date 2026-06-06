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

"""Evidence-backed contract report summaries."""

from __future__ import annotations

from dataclasses import dataclass

from pysymex.contracts.ir.evidence import EvidenceResult
from pysymex.contracts.reports.adapters import extract_counterexample_from_model
from pysymex.contracts.runtime.capture import RuntimeContractOutcome
from pysymex.contracts.types import ContractKind, VerificationResult
from pysymex.execution.executors.verified.types import ContractIssue


_OUTCOME_PRIORITY = {
    VerificationResult.VERIFIED: 0,
    VerificationResult.UNKNOWN: 1,
    VerificationResult.UNREACHABLE: 1,
    VerificationResult.UNSUPPORTED: 2,
    VerificationResult.VIOLATED: 3,
}


@dataclass(frozen=True, slots=True)
class RuntimeContractSummary:
    """Selected runtime contract outcomes projected for verified execution."""

    issues: list[ContractIssue]
    evidence: list[EvidenceResult]
    nested_contract_count: int
    verified_count: int


def aggregate_runtime_contract_outcomes(
    outcomes: list[RuntimeContractOutcome],
    target_identity: int,
) -> RuntimeContractSummary:
    """Convert runtime outcomes to one report result per evaluated obligation."""
    selected: dict[tuple[object, ...], RuntimeContractOutcome] = {}
    for outcome in outcomes:
        key = outcome.obligation_key
        current = selected.get(key)
        if current is None or _OUTCOME_PRIORITY[outcome.result] > _OUTCOME_PRIORITY[current.result]:
            selected[key] = outcome

    issues: list[ContractIssue] = []
    for outcome in selected.values():
        if outcome.result is VerificationResult.VERIFIED:
            continue
        source_issue = outcome.issue
        source_model = source_issue.model if source_issue is not None else None
        if source_model is None and outcome.evidence is not None:
            source_model = outcome.evidence.model
        issues.append(
            ContractIssue(
                kind=outcome.kind,
                condition=outcome.condition,
                message=(
                    source_issue.message
                    if source_issue is not None
                    else outcome.evidence.message
                    if outcome.evidence is not None
                    else outcome.condition
                ),
                line_number=outcome.line_number,
                function_name=outcome.function_name,
                counterexample=extract_counterexample_from_model(source_model),
                severity=outcome.severity,
                result=outcome.result,
                evidence=outcome.evidence,
            )
        )
    evidence = [outcome.evidence for outcome in selected.values() if outcome.evidence is not None]
    nested_count = sum(
        outcome.function_identity != target_identity and outcome.kind is not ContractKind.ASSUMES
        for outcome in selected.values()
    )
    verified_count = sum(
        outcome.evidence is not None and outcome.evidence.status is VerificationResult.VERIFIED
        for outcome in selected.values()
    )
    return RuntimeContractSummary(
        issues=issues,
        evidence=evidence,
        nested_contract_count=nested_count,
        verified_count=verified_count,
    )


__all__ = ["RuntimeContractSummary", "aggregate_runtime_contract_outcomes"]
