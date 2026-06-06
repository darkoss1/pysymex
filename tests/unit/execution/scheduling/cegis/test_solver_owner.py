from __future__ import annotations

from typing import cast

import z3

from pysymex.core.state.record import VMState
from pysymex.execution.frontier import (
    FrontierStateSnapshot,
    build_frontier_checkpoint,
)
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceCertificateKind,
    EvidenceOutcomeKind,
    EvidenceOwner,
    evaluate_checkpoint_unsat_core_action,
    plan_evidence_application,
)


def _solver_action(
    capsule_id: str, *, owner: EvidenceOwner = EvidenceOwner.SOLVER
) -> EvidenceAction:
    return EvidenceAction(
        action_id=f"{capsule_id}:unsat_core",
        capsule_id=capsule_id,
        kind=EvidenceActionKind.TRY_UNSAT_CORE,
        owner=owner,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def test_checkpoint_unsat_core_owner_builds_certificate_from_reconstruction() -> None:
    """The shadow solver owner can certify an exact reconstructed UNSAT capsule."""
    x = z3.Int("cegis_owner_unsat")
    checkpoint = build_frontier_checkpoint(
        VMState(path_constraints=[x > 0, x <= 0], pending_constraint_count=2),
        capsule_id="path:0",
    )

    outcome = evaluate_checkpoint_unsat_core_action(_solver_action("path:0"), checkpoint)
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert outcome.certificate is not None
    assert outcome.certificate.kind is EvidenceCertificateKind.UNSAT_CORE
    assert outcome.certificate.core_indices
    assert plan.can_remove is True
    assert plan.removable_state_ids == (0,)


def test_checkpoint_unsat_core_owner_covers_exact_live_core_supersets() -> None:
    """A real UNSAT core can cover only live checkpoints containing the exact core."""
    x = z3.Int("cegis_owner_unsat_reuse")
    positive = x > 0
    nonpositive = x <= 0
    selected = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:0",
    )
    duplicate = build_frontier_checkpoint(
        VMState(path_constraints=[positive, nonpositive], pending_constraint_count=2),
        capsule_id="path:1",
    )
    sat_sibling = build_frontier_checkpoint(
        VMState(path_constraints=[positive], pending_constraint_count=1),
        capsule_id="path:2",
    )

    outcome = evaluate_checkpoint_unsat_core_action(
        _solver_action("path:0"),
        selected,
        candidate_checkpoints=(selected, duplicate, sat_sibling),
    )
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0, 1, 2),
        capsules_by_state_id={
            0: selected.capsule,
            1: duplicate.capsule,
            2: sat_sibling.capsule,
        },
    )

    assert outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert outcome.valid_removed_capsule_ids == ("path:0", "path:1")
    assert plan.can_remove is True
    assert plan.removable_state_ids == (0, 1)


def test_checkpoint_unsat_core_owner_keeps_sat_non_removing() -> None:
    """SAT reconstructed constraints cannot produce an UNSAT removal certificate."""
    x = z3.Int("cegis_owner_sat")
    checkpoint = build_frontier_checkpoint(
        VMState(path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:0",
    )

    outcome = evaluate_checkpoint_unsat_core_action(_solver_action("path:0"), checkpoint)
    plan = plan_evidence_application(
        outcome,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
    )

    assert outcome.kind is EvidenceOutcomeKind.SAT
    assert outcome.certificate is None
    assert plan.can_remove is False


def test_checkpoint_unsat_core_owner_rejects_action_capsule_mismatch() -> None:
    """A solver action cannot certify a different checkpoint capsule."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")

    outcome = evaluate_checkpoint_unsat_core_action(_solver_action("path:1"), checkpoint)

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_unsat_core_owner_rejects_non_solver_owner() -> None:
    """Only solver-owned UNSAT-core actions may run the solver evaluator."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")

    outcome = evaluate_checkpoint_unsat_core_action(
        _solver_action("path:0", owner=EvidenceOwner.VM),
        checkpoint,
    )

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()


def test_checkpoint_unsat_core_owner_rejects_digest_mismatch() -> None:
    """Checkpoint drift remains inconclusive and cannot produce solver proof."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")
    snapshot = cast("FrontierStateSnapshot", object.__getattribute__(checkpoint, "_snapshot"))
    object.__setattr__(snapshot, "pc", 2)

    outcome = evaluate_checkpoint_unsat_core_action(_solver_action("path:0"), checkpoint)

    assert outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert outcome.certificate is None
    assert outcome.valid_removed_capsule_ids == ()
