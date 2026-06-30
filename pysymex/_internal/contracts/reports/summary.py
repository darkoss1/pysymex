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

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import EvidenceResult, SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.reports.adapters import extract_counterexample_from_model
from pysymex._internal.contracts.reports.issues import ContractIssue
from pysymex.contracts import ContractKind

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.contracts.runtime.capture import RuntimeContractOutcome

_OUTCOME_PRIORITY = {
    VerificationResult.VERIFIED: 0,
    VerificationResult.UNKNOWN: 1,
    VerificationResult.UNREACHABLE: 1,
    VerificationResult.UNSUPPORTED: 2,
    VerificationResult.VIOLATED: 3,
}
_CONTRACT_PROOF_UNSAFE_DEGRADATION_LABELS = frozenset(
    (
        "unmodeled_call_abstraction",
        "solver_unknown_path_feasibility",
        "unsupported_vm_state",
    ),
)
_CONTRACT_PROOF_UNSAFE_DEGRADATION_PREFIXES = ("resource_limit_", "unsupported_")
_CONTRACT_PROOF_UNSAFE_DEGRADATION_SUFFIXES = (
    "_abstraction",
    "_feasibility_unknown",
    "_havoc",
    "_type_uncertain",
)
_EXECUTION_PRECISION_SENSITIVE_QUERY_KINDS = frozenset(
    (
        QueryKind.POSTCONDITION,
        QueryKind.FRAME_CONDITION,
        QueryKind.PURE_EFFECT,
        QueryKind.INVARIANT_EXIT,
    ),
)


@dataclass(frozen=True, slots=True)
class RuntimeContractSummary:
    """Selected runtime contract outcomes projected for verified execution."""

    issues: list[ContractIssue]
    evidence: list[EvidenceResult]
    nested_contract_count: int
    verified_count: int


def aggregate_runtime_outcomes(
    outcomes: list[RuntimeContractOutcome],
    target_identity: int,
    *,
    degraded_passes: Iterable[str] = (),
) -> RuntimeContractSummary:
    """Convert runtime outcomes to one report result per evaluated obligation."""
    selected: dict[tuple[object, ...], RuntimeContractOutcome] = {}
    for outcome in outcomes:
        key = _outcome_report_key(outcome, target_identity)
        current = selected.get(key)
        if current is None or _OUTCOME_PRIORITY[outcome.result] > _OUTCOME_PRIORITY[current.result]:
            selected[key] = outcome

    proof_degradation_labels = _unsafe_proof_degradation_labels(degraded_passes)
    issues: list[ContractIssue] = []
    for outcome in selected.values():
        effective_result = _effective_contract_result(outcome, proof_degradation_labels)
        effective_evidence = _effective_contract_evidence(outcome, proof_degradation_labels)
        if effective_result is VerificationResult.VERIFIED:
            continue
        source_issue = outcome.issue
        source_model = source_issue.model if source_issue is not None else None
        if source_model is None and effective_evidence is not None:
            source_model = effective_evidence.model
        message = outcome.condition
        if effective_evidence is not None and effective_evidence.status is not outcome.result:
            message = effective_evidence.message
        elif source_issue is not None:
            message = source_issue.message
        elif effective_evidence is not None:
            message = effective_evidence.message
        issues.append(
            ContractIssue(
                kind=outcome.kind,
                condition=outcome.condition,
                message=message,
                line_number=outcome.line_number,
                function_name=outcome.function_name,
                counterexample=extract_counterexample_from_model(source_model),
                severity=outcome.severity,
                result=effective_result,
                evidence=effective_evidence,
            ),
        )
    evidence = [
        effective_evidence
        for outcome in selected.values()
        if (effective_evidence := _effective_contract_evidence(outcome, proof_degradation_labels))
        is not None
    ]
    nested_count = sum(
        outcome.function_identity != target_identity and outcome.kind is not ContractKind.ASSUMES
        for outcome in selected.values()
    )
    verified_count = sum(
        _effective_contract_result(outcome, proof_degradation_labels) is VerificationResult.VERIFIED
        and _effective_contract_evidence(outcome, proof_degradation_labels) is not None
        for outcome in selected.values()
    )
    return RuntimeContractSummary(
        issues=issues,
        evidence=evidence,
        nested_contract_count=nested_count,
        verified_count=verified_count,
    )


def _unsafe_proof_degradation_labels(labels: Iterable[str]) -> tuple[str, ...]:
    """Return degradation labels that can invalidate a contract proof claim."""
    return tuple(label for label in labels if _can_invalidate_contract_proof(label))


def _outcome_report_key(
    outcome: RuntimeContractOutcome,
    target_identity: int,
) -> tuple[object, ...]:
    """Return the declared-obligation key used for report counters and issues."""
    evidence = outcome.evidence
    if evidence is None or outcome.function_identity != target_identity:
        return outcome.obligation_key

    obligation = evidence.obligation
    call_site_pc = obligation.pc if obligation.hook is ObligationHook.CALL_SITE else None
    return (
        outcome.kind,
        outcome.condition,
        outcome.function_identity,
        outcome.line_number,
        obligation.clause.clause_id,
        obligation.hook,
        obligation.query_kind,
        call_site_pc,
    )


def _can_invalidate_contract_proof(label: str) -> bool:
    """Return whether a degraded execution label may hide contract-relevant behavior."""
    return (
        label in _CONTRACT_PROOF_UNSAFE_DEGRADATION_LABELS
        or label.startswith(_CONTRACT_PROOF_UNSAFE_DEGRADATION_PREFIXES)
        or label.endswith(_CONTRACT_PROOF_UNSAFE_DEGRADATION_SUFFIXES)
    )


def _effective_contract_result(
    outcome: RuntimeContractOutcome,
    proof_degradation_labels: tuple[str, ...],
) -> VerificationResult:
    """Downgrade definite outcomes when execution precision loss can hide behavior."""
    if outcome.result in {
        VerificationResult.VERIFIED,
        VerificationResult.VIOLATED,
    } and _degradation_invalidates_outcome(outcome, proof_degradation_labels):
        return VerificationResult.UNKNOWN
    return outcome.result


def _effective_contract_evidence(
    outcome: RuntimeContractOutcome,
    proof_degradation_labels: tuple[str, ...],
) -> EvidenceResult | None:
    """Return evidence with verified proofs downgraded under unsafe degradation."""
    evidence = outcome.evidence
    if (
        evidence is None
        or outcome.result not in {VerificationResult.VERIFIED, VerificationResult.VIOLATED}
        or not _degradation_invalidates_outcome(outcome, proof_degradation_labels)
    ):
        return evidence
    labels = ", ".join(proof_degradation_labels)
    outcome_noun = "violation" if outcome.result is VerificationResult.VIOLATED else "proof"
    return replace(
        evidence,
        status=VerificationResult.UNKNOWN,
        solver_status=SolverStatus.UNKNOWN,
        message=(
            f"Contract '{outcome.condition}' was not counted as a definite {outcome_noun} "
            f"because analysis "
            f"degraded: {labels}"
        ),
        model=None,
        unsupported_reasons=_append_precision_loss_reason(evidence.unsupported_reasons),
    )


def _append_precision_loss_reason(
    reasons: tuple[UnsupportedReason, ...],
) -> tuple[UnsupportedReason, ...]:
    """Add the precision-loss reason once while preserving existing reason order."""
    if UnsupportedReason.PRECISION_LOSS in reasons:
        return reasons
    return (*reasons, UnsupportedReason.PRECISION_LOSS)


def _degradation_invalidates_outcome(
    outcome: RuntimeContractOutcome,
    proof_degradation_labels: tuple[str, ...],
) -> bool:
    """Return whether degraded execution can invalidate this obligation outcome."""
    if not proof_degradation_labels:
        return False
    evidence = outcome.evidence
    if evidence is None:
        return outcome.kind not in {ContractKind.REQUIRES, ContractKind.ASSUMES}

    obligation = evidence.obligation
    if obligation.query_kind in _EXECUTION_PRECISION_SENSITIVE_QUERY_KINDS:
        return True
    return obligation.hook is ObligationHook.FRAME_EXIT
