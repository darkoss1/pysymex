from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.execution.frontier import build_frontier_checkpoint, build_shadow_capsule
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificateKind,
    EvidenceOutcomeKind,
    EvidenceOwner,
    evaluate_capsule_dominance_action,
    evaluate_checkpoint_dominance_action,
    plan_evidence_application,
)


def _dominance_action(
    capsule_id: str,
    *,
    kind: EvidenceActionKind = EvidenceActionKind.CHECK_DOMINANCE,
    owner: EvidenceOwner = EvidenceOwner.FRONTIER,
) -> EvidenceAction:
    return EvidenceAction(
        action_id=f"{capsule_id}:dominance",
        capsule_id=capsule_id,
        kind=kind,
        owner=owner,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def test_checkpoint_dominance_owner_certifies_exact_duplicate_candidate() -> None:
    """Structurally duplicate checkpoints can be certified as exact dominance removal."""
    x = z3.Int("cegis_dominance_equal")
    subject = build_frontier_checkpoint(
        VMState(pc=3, path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:0",
    )
    candidate = build_frontier_checkpoint(
        VMState(pc=3, path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:1",
    )

    outcome = evaluate_checkpoint_dominance_action(
        _dominance_action("path:0"),
        subject,
        (candidate,),
    )
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0, 1),
        capsules_by_state_id={0: subject.capsule, 1: candidate.capsule},
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_DOMINATED
    assert outcome.certificate is not None
    assert outcome.certificate.kind is EvidenceCertificateKind.DOMINANCE
    assert outcome.valid_removed_capsule_ids == ("path:1",)
    assert plan.can_remove is True
    assert plan.removable_state_ids == (1,)


def test_checkpoint_dominance_owner_rejects_different_digest_candidate() -> None:
    """Different phase-0 semantic digests are not dominance evidence."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")
    candidate = build_frontier_checkpoint(VMState(pc=4), capsule_id="path:1")

    outcome = evaluate_checkpoint_dominance_action(
        _dominance_action("path:0"),
        subject,
        (candidate,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_dominance_owner_ignores_subject_self_candidate() -> None:
    """A dominance owner never certifies removal of its selected subject capsule."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")

    outcome = evaluate_checkpoint_dominance_action(
        _dominance_action("path:0"),
        subject,
        (subject,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_dominance_owner_rejects_wrong_action_owner_or_kind() -> None:
    """Only frontier-owned dominance actions may run dominance evaluation."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")
    candidate = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:1")

    for action in (
        _dominance_action("path:0", owner=EvidenceOwner.SOLVER),
        _dominance_action("path:0", kind=EvidenceActionKind.TRY_UNSAT_CORE),
    ):
        outcome = evaluate_checkpoint_dominance_action(action, subject, (candidate,))
        assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
        assert outcome.certificate is None
        assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_dominance_owner_rejects_action_subject_mismatch() -> None:
    """A dominance action must name the selected subject capsule."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")
    candidate = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:1")

    outcome = evaluate_checkpoint_dominance_action(
        _dominance_action("path:1"),
        subject,
        (candidate,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_capsule_only_dominance_owner_is_inconclusive_without_checkpoint() -> None:
    """Capsule digests can propose a bid but cannot certify dominance alone."""
    subject = build_shadow_capsule(VMState(pc=3), capsule_id="path:0")
    candidate = build_shadow_capsule(VMState(pc=3), capsule_id="path:1")

    outcome = evaluate_capsule_dominance_action(
        _dominance_action("path:0"),
        subject,
        (candidate,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_capsule_only_dominance_owner_rejects_wrong_action_owner_or_kind() -> None:
    """Capsule-only dominance still requires a frontier-owned dominance action."""
    subject = build_shadow_capsule(VMState(pc=3), capsule_id="path:0")
    candidate = build_shadow_capsule(VMState(pc=3), capsule_id="path:1")

    for action in (
        _dominance_action("path:0", owner=EvidenceOwner.SOLVER),
        _dominance_action("path:0", kind=EvidenceActionKind.TRY_UNSAT_CORE),
    ):
        outcome = evaluate_capsule_dominance_action(action, subject, (candidate,))
        assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
        assert outcome.certificate is None
        assert outcome.valid_removed_capsule_ids == ()


def test_capsule_only_dominance_owner_rejects_action_subject_mismatch() -> None:
    """A capsule-only dominance action must still identify the selected subject."""
    subject = build_shadow_capsule(VMState(pc=3), capsule_id="path:0")
    candidate = build_shadow_capsule(VMState(pc=3), capsule_id="path:1")

    outcome = evaluate_capsule_dominance_action(
        _dominance_action("path:1"),
        subject,
        (candidate,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
