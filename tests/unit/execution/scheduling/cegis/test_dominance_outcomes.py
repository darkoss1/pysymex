from __future__ import annotations

from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificateKind,
    EvidenceOwner,
    EvidenceOutcomeKind,
    dominance_certificate_outcome,
)


def _dominance_action(action_id: str, *, capsule_id: str = "selected") -> EvidenceAction:
    return EvidenceAction(
        action_id=action_id,
        capsule_id=capsule_id,
        kind=EvidenceActionKind.CHECK_DOMINANCE,
        owner=EvidenceOwner.FRONTIER,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def test_dominance_certificate_outcome_builds_exact_certificate() -> None:
    """Frontier-owned exact dominance can certify dominated sibling capsules."""
    outcome = dominance_certificate_outcome(
        _dominance_action("dominance"),
        dominated_capsule_ids=("dominated-a", "dominated-b"),
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_DOMINATED
    assert outcome.certificate is not None
    assert outcome.certificate.kind is EvidenceCertificateKind.DOMINANCE
    assert outcome.valid_removed_capsule_ids == ("dominated-a", "dominated-b")
    assert outcome.has_invalid_removal_attempt is False


def test_dominance_certificate_outcome_rejects_mismatched_action() -> None:
    """Only dominance-check actions can produce dominance certificates."""
    action = EvidenceAction(
        action_id="solver-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )

    outcome = dominance_certificate_outcome(
        action,
        dominated_capsule_ids=("dominated",),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_dominance_certificate_outcome_rejects_empty_dominance() -> None:
    """No dominated capsules means no removal certificate."""
    outcome = dominance_certificate_outcome(
        _dominance_action("dominance"), dominated_capsule_ids=()
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False


def test_dominance_certificate_outcome_rejects_selected_capsule_removal() -> None:
    """Dominance certificates cannot remove their selected subject capsule."""
    outcome = dominance_certificate_outcome(
        _dominance_action("dominance"),
        dominated_capsule_ids=("selected", "dominated"),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is False
