from __future__ import annotations

from typing import cast

from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificate,
    EvidenceCertificateKind,
    EvidenceOwner,
    EvidenceOutcome,
    EvidenceOutcomeKind,
)


def _action(
    action_id: str,
    *,
    capsule_id: str = "capsule",
    kind: EvidenceActionKind = EvidenceActionKind.EXECUTE_STEP,
    owner: EvidenceOwner = EvidenceOwner.VM,
    may_remove_work: bool = False,
    requires_exact_evidence: bool = False,
) -> EvidenceAction:
    return EvidenceAction(
        action_id=action_id,
        capsule_id=capsule_id,
        kind=kind,
        owner=owner,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=may_remove_work,
        requires_exact_evidence=requires_exact_evidence,
    )


def test_exact_owner_outcome_without_certificate_cannot_remove_work() -> None:
    """The legacy no-certificate exact-removal fallback is disabled."""
    action = _action(
        "exact-core",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("capsule",),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_exact_owner_outcome_cannot_remove_unproven_sibling_capsule() -> None:
    """Exact phase-0 outcomes cannot remove sibling capsules without proof records."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected", "sat-sibling"),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_exact_owner_certificate_can_validate_covered_sibling_removal() -> None:
    """A matching exact certificate can expose all capsules it covers."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected", "covered-sibling"),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.UNSAT_CORE,
            subject_capsule_id="selected",
            covered_capsule_ids=("selected", "covered-sibling"),
        ),
    )

    assert outcome.valid_removed_capsule_ids == ("selected", "covered-sibling")
    assert outcome.has_invalid_removal_attempt is False


def test_certificate_cover_membership_is_exact() -> None:
    """Certificate coverage is exact capsule-ID membership."""
    certificate = EvidenceCertificate(
        kind=EvidenceCertificateKind.UNSAT_CORE,
        subject_capsule_id="selected",
        covered_capsule_ids=("selected", "covered-sibling"),
    )

    assert certificate.covers("selected") is True
    assert certificate.covers("sat-sibling") is False


def test_exact_owner_certificate_rejects_subject_mismatch() -> None:
    """A certificate for another selected capsule cannot validate removal."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected",),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.UNSAT_CORE,
            subject_capsule_id="other-selected",
            covered_capsule_ids=("selected",),
        ),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_exact_owner_certificate_rejects_malformed_certificate_kind() -> None:
    """A malformed certificate kind cannot validate removal."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    certificate = EvidenceCertificate(
        kind=EvidenceCertificateKind.UNSAT_CORE,
        subject_capsule_id="selected",
        covered_capsule_ids=("selected",),
    )
    object.__setattr__(certificate, "kind", cast(EvidenceCertificateKind, object()))
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected",),
        certificate=certificate,
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_exact_owner_certificate_rejects_uncovered_sibling_removal() -> None:
    """A certificate cannot remove capsules outside its covered set."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected", "uncovered-sibling"),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.UNSAT_CORE,
            subject_capsule_id="selected",
            covered_capsule_ids=("selected",),
        ),
    )

    assert outcome.valid_removed_capsule_ids == ("selected",)
    assert outcome.has_invalid_removal_attempt is True


def test_mismatched_owner_certificate_cannot_validate_removal() -> None:
    """Dominance certificates cannot validate UNSAT-core removals."""
    action = _action(
        "exact-core",
        capsule_id="selected",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_UNSAT,
        removed_capsule_ids=("selected",),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.DOMINANCE,
            subject_capsule_id="selected",
            covered_capsule_ids=("selected",),
        ),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_unsat_certificate_cannot_validate_dominance_removal() -> None:
    """UNSAT-core certificates cannot validate dominance removals."""
    action = _action(
        "dominance",
        capsule_id="selected",
        kind=EvidenceActionKind.CHECK_DOMINANCE,
        owner=EvidenceOwner.FRONTIER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXACT_DOMINATED,
        removed_capsule_ids=("dominated",),
        certificate=EvidenceCertificate(
            kind=EvidenceCertificateKind.UNSAT_CORE,
            subject_capsule_id="selected",
            covered_capsule_ids=("dominated",),
        ),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True


def test_non_exact_owner_outcome_cannot_remove_work() -> None:
    """SAT, unknown, timeout, unsupported, and inconclusive outcomes are non-removing."""
    action = _action(
        "unknown-core",
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=EvidenceOwner.SOLVER,
        may_remove_work=True,
        requires_exact_evidence=True,
    )

    for kind in (
        EvidenceOutcomeKind.SAT,
        EvidenceOutcomeKind.INCONCLUSIVE,
        EvidenceOutcomeKind.UNSUPPORTED,
        EvidenceOutcomeKind.SOLVER_UNKNOWN,
        EvidenceOutcomeKind.TIMEOUT,
    ):
        outcome = EvidenceOutcome(
            action=action,
            kind=kind,
            removed_capsule_ids=("capsule",),
        )
        assert outcome.valid_removed_capsule_ids == ()
        assert outcome.has_invalid_removal_attempt is True


def test_non_removing_action_cannot_smuggle_removal_ids() -> None:
    """Execution actions cannot remove work by returning capsule IDs."""
    action = _action("execute", kind=EvidenceActionKind.EXECUTE_STEP)
    outcome = EvidenceOutcome(
        action=action,
        kind=EvidenceOutcomeKind.EXECUTED,
        removed_capsule_ids=("capsule",),
    )

    assert outcome.valid_removed_capsule_ids == ()
    assert outcome.has_invalid_removal_attempt is True
