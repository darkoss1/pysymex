from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoints import build_frontier_checkpoint
from pysymex._internal.execution.scheduling.cegis.application import plan_evidence_application
from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.outcomes.types import (
    EvidenceCertificateKind,
    EvidenceOutcomeKind,
)
from pysymex._internal.execution.scheduling.cegis.owners import choose_checkpoint_dominance_action


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

    outcome = choose_checkpoint_dominance_action(
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

    outcome = choose_checkpoint_dominance_action(
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

    outcome = choose_checkpoint_dominance_action(
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
        outcome = choose_checkpoint_dominance_action(action, subject, (candidate,))
        assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
        assert outcome.certificate is None
        assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_dominance_owner_rejects_action_subject_mismatch() -> None:
    """A dominance action must name the selected subject capsule."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")
    candidate = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:1")

    outcome = choose_checkpoint_dominance_action(
        _dominance_action("path:1"),
        subject,
        (candidate,),
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
