from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoints import build_frontier_checkpoint
from pysymex._internal.execution.frontier.obligations.capsules import build_shadow_capsule
from pysymex._internal.execution.scheduling.cegis.bids.capsules import shadow_bids_for_capsule
from pysymex._internal.execution.scheduling.cegis.bids.types import (
    EvidenceAction,
    EvidenceActionKind,
    EvidenceBid,
    EvidenceOwner,
)
from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
from pysymex._internal.execution.scheduling.cegis.evaluation.decision import (
    evaluate_shadow_decision,
)
from pysymex._internal.execution.scheduling.cegis.evaluation.decision import (
    evaluate_shadow_decision as evaluate_shadow_decision_owner,
)
from pysymex._internal.execution.scheduling.cegis.evaluation.frontier import (
    evaluate_shadow_frontier,
)
from pysymex._internal.execution.scheduling.cegis.evaluation.frontier import (
    evaluate_shadow_frontier as evaluate_shadow_frontier_owner,
)
from pysymex._internal.execution.scheduling.cegis.outcomes.types import EvidenceOutcomeKind
from pysymex._internal.execution.scheduling.cegis.policy import (
    SchedulerDecision,
    select_deterministic_bid,
)


def _dominance_action(capsule_id: str) -> EvidenceAction:
    return EvidenceAction(
        action_id=f"{capsule_id}:dominance",
        capsule_id=capsule_id,
        kind=EvidenceActionKind.CHECK_DOMINANCE,
        owner=EvidenceOwner.FRONTIER,
        required_budget=BudgetVector(path_budget=1),
        may_remove_work=True,
        requires_exact_evidence=True,
    )


def _decision_for_action(action: EvidenceAction) -> SchedulerDecision:
    bid = EvidenceBid(
        action=action,
        expected_detector_gain=0.0,
        expected_coverage_gain=0.0,
        expected_core_reuse_gain=0.0,
        expected_dominance_gain=1.0,
        expected_pruned_units=1,
        expected_uncertainty_reduction=0.0,
        expected_cost=action.required_budget,
        confidence=1.0,
        explanation="test decision",
    )
    return SchedulerDecision(
        selected_bid=bid,
        rejected_action_ids=(),
        active_budget=BudgetVector(path_budget=1),
        score=bid.score,
    )


def _generous_budget() -> BudgetVector:
    return BudgetVector(
        wall_time_ms=10.0,
        solver_time_ms=10.0,
        resident_units=10,
        reconstruction_units=10,
        path_budget=10,
    )


def test_shadow_evaluation_public_exports_point_to_direct_owners() -> None:
    """Package-level CEGIS evaluation exports stay wired to direct owners."""
    assert evaluate_shadow_decision is evaluate_shadow_decision_owner
    assert evaluate_shadow_frontier is evaluate_shadow_frontier_owner


def test_evaluate_shadow_decision_runs_solver_owner_and_plans_unsat_removal() -> None:
    """A selected solver bid produces a dry-run removal plan, not queue mutation."""
    x = z3.Int("cegis_shadow_eval_unsat")
    checkpoint = build_frontier_checkpoint(
        VMState(path_constraints=[x > 0, x <= 0], pending_constraint_count=2),
        capsule_id="path:0",
    )
    decision = select_deterministic_bid(
        shadow_bids_for_capsule(checkpoint.capsule),
        active_budget=_generous_budget(),
    )
    assert decision is not None
    assert decision.selected_bid.action.kind is EvidenceActionKind.TRY_UNSAT_CORE

    evaluation = evaluate_shadow_decision(
        decision,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
        checkpoints_by_state_id={0: checkpoint},
    )

    assert evaluation.has_decision is True
    assert evaluation.selected_state_id == 0
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is True
    assert evaluation.application_plan.removable_state_ids == (0,)
    assert evaluation.can_remove is True


def test_evaluate_shadow_frontier_selects_and_plans_live_solver_bid() -> None:
    """The full shadow preview cycle selects a live bid and dry-runs owner evidence."""
    x = z3.Int("cegis_shadow_frontier_unsat")
    checkpoint = build_frontier_checkpoint(
        VMState(path_constraints=[x > 0, x <= 0], pending_constraint_count=2),
        capsule_id="path:0",
    )

    evaluation = evaluate_shadow_frontier(
        active_budget=_generous_budget(),
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
        checkpoints_by_state_id={0: checkpoint},
    )

    assert evaluation.has_decision is True
    assert evaluation.decision is not None
    assert evaluation.decision.selected_bid.action.kind is EvidenceActionKind.TRY_UNSAT_CORE
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.EXACT_UNSAT
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is True
    assert evaluation.application_plan.removable_state_ids == (0,)


def test_evaluate_shadow_frontier_selects_duplicate_dominance_bid() -> None:
    """Frontier-level duplicate bids can produce dry-run dominated-sibling plans."""
    subject = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:0")
    candidate = build_frontier_checkpoint(VMState(pc=3), capsule_id="path:1")

    evaluation = evaluate_shadow_frontier(
        active_budget=_generous_budget(),
        live_state_ids=(0, 1),
        capsules_by_state_id={0: subject.capsule, 1: candidate.capsule},
        checkpoints_by_state_id={0: subject, 1: candidate},
    )

    assert evaluation.has_decision is True
    assert evaluation.selected_state_id == 0
    assert evaluation.decision is not None
    assert evaluation.decision.selected_bid.action.kind is EvidenceActionKind.CHECK_DOMINANCE
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.EXACT_DOMINATED
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is True
    assert evaluation.application_plan.removable_state_ids == (1,)


def test_evaluate_shadow_decision_keeps_execute_action_non_removing() -> None:
    """The shadow harness does not execute VM actions or treat them as proof."""
    checkpoint = build_frontier_checkpoint(VMState(pc=5), capsule_id="path:0")
    decision = select_deterministic_bid(
        shadow_bids_for_capsule(checkpoint.capsule),
        active_budget=_generous_budget(),
    )
    assert decision is not None
    assert decision.selected_bid.action.kind is EvidenceActionKind.EXECUTE_STEP

    evaluation = evaluate_shadow_decision(
        decision,
        live_state_ids=(0,),
        capsules_by_state_id={0: checkpoint.capsule},
        checkpoints_by_state_id={0: checkpoint},
    )

    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is False
    assert evaluation.application_plan.invalid_removal_attempt is False
    assert evaluation.can_remove is False


def test_evaluate_shadow_decision_runs_frontier_dominance_owner() -> None:
    """A selected dominance bid can produce a dry-run dominated-sibling plan."""
    x = z3.Int("cegis_shadow_eval_dom")
    subject = build_frontier_checkpoint(
        VMState(pc=3, path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:0",
    )
    candidate = build_frontier_checkpoint(
        VMState(pc=3, path_constraints=[x > 0], pending_constraint_count=1),
        capsule_id="path:1",
    )

    evaluation = evaluate_shadow_decision(
        _decision_for_action(_dominance_action("path:0")),
        live_state_ids=(0, 1),
        capsules_by_state_id={0: subject.capsule, 1: candidate.capsule},
        checkpoints_by_state_id={0: subject, 1: candidate},
    )

    assert evaluation.selected_state_id == 0
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.EXACT_DOMINATED
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is True
    assert evaluation.application_plan.removable_state_ids == (1,)
    assert evaluation.can_remove is True


def test_evaluate_shadow_decision_missing_live_capsule_is_inconclusive() -> None:
    """A selected action for a non-live capsule cannot produce removable work."""
    capsule = build_shadow_capsule(VMState(pc=1), capsule_id="path:0")

    evaluation = evaluate_shadow_decision(
        _decision_for_action(_dominance_action("path:missing")),
        live_state_ids=(0,),
        capsules_by_state_id={0: capsule},
        checkpoints_by_state_id={},
    )

    assert evaluation.selected_state_id is None
    assert evaluation.outcome is not None
    assert evaluation.outcome.kind is EvidenceOutcomeKind.INCONCLUSIVE
    assert evaluation.application_plan is not None
    assert evaluation.application_plan.can_remove is False
    assert evaluation.can_remove is False


def test_evaluate_shadow_decision_none_returns_no_plan() -> None:
    """No selected bid remains an observable no-op."""
    evaluation = evaluate_shadow_decision(
        None,
        live_state_ids=(),
        capsules_by_state_id={},
        checkpoints_by_state_id={},
    )

    assert evaluation.has_decision is False
    assert evaluation.outcome is None
    assert evaluation.application_plan is None
    assert evaluation.selected_state_id is None
    assert evaluation.can_remove is False


def test_evaluate_shadow_frontier_without_live_capsules_returns_no_plan() -> None:
    """Stale shadow maps cannot produce a selected CEGIS decision."""
    checkpoint = build_frontier_checkpoint(VMState(pc=1), capsule_id="path:0")

    evaluation = evaluate_shadow_frontier(
        active_budget=_generous_budget(),
        live_state_ids=(),
        capsules_by_state_id={0: checkpoint.capsule},
        checkpoints_by_state_id={0: checkpoint},
    )

    assert evaluation.has_decision is False
    assert evaluation.outcome is None
    assert evaluation.application_plan is None
    assert evaluation.can_remove is False
