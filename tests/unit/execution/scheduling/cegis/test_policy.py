from __future__ import annotations

import z3

from pysymex.core.state.record import VMState
from pysymex.execution.frontier import build_shadow_capsule
from pysymex.execution.scheduling.cegis import (
    BudgetVector,
    EvidenceAction,
    EvidenceActionKind,
    EvidenceBid,
    EvidenceOwner,
    feature_vector_from_capsule,
    select_deterministic_bid,
    shadow_bids_for_capsule,
    shadow_bids_for_frontier_capsules,
)


def _bid(
    action_id: str,
    *,
    capsule_id: str = "capsule",
    kind: EvidenceActionKind = EvidenceActionKind.EXECUTE_STEP,
    budget: BudgetVector | None = None,
    may_remove_work: bool = False,
    requires_exact_evidence: bool = False,
    gain: float = 1.0,
) -> EvidenceBid:
    required_budget = budget if budget is not None else BudgetVector(path_budget=1)
    return EvidenceBid(
        action=EvidenceAction(
            action_id=action_id,
            capsule_id=capsule_id,
            kind=kind,
            owner=EvidenceOwner.VM,
            required_budget=required_budget,
            may_remove_work=may_remove_work,
            requires_exact_evidence=requires_exact_evidence,
        ),
        expected_detector_gain=gain,
        expected_coverage_gain=0.0,
        expected_core_reuse_gain=0.0,
        expected_dominance_gain=0.0,
        expected_pruned_units=0,
        expected_uncertainty_reduction=0.0,
        expected_cost=required_budget,
        confidence=1.0,
        explanation="test bid",
    )


def test_feature_vector_and_shadow_bids_are_derived_from_capsule() -> None:
    """CEGIS phase-0 inputs come from POLAR capsules, not live queue mutation."""
    x = z3.Int("cegis_feature_x")
    capsule = build_shadow_capsule(
        VMState(path_constraints=[x > 0], pending_constraint_count=1, pc=23, depth=5),
        capsule_id="capsule-feature",
    )

    features = feature_vector_from_capsule(capsule, memory_pressure=0.25)
    bids = shadow_bids_for_capsule(capsule, memory_pressure=0.25)

    assert features.capsule_id == "capsule-feature"
    assert features.pc == 23
    assert features.depth == 5
    assert features.constraint_atom_count == 1
    assert features.pending_constraint_count == 1
    assert features.memory_pressure == 0.25
    assert {bid.action.kind for bid in bids} == {
        EvidenceActionKind.EXECUTE_STEP,
        EvidenceActionKind.TRY_UNSAT_CORE,
    }
    assert all(bid.action.capsule_id == "capsule-feature" for bid in bids)


def test_frontier_shadow_bids_add_dominance_for_duplicate_capsules() -> None:
    """Dominance bids require live-frontier duplicate context."""
    subject = build_shadow_capsule(VMState(pc=23), capsule_id="path:0")
    duplicate = build_shadow_capsule(VMState(pc=23), capsule_id="path:1")
    unique = build_shadow_capsule(VMState(pc=24), capsule_id="path:2")

    bids = shadow_bids_for_frontier_capsules((subject, duplicate, unique))

    dominance_bids = [bid for bid in bids if bid.action.kind is EvidenceActionKind.CHECK_DOMINANCE]
    assert len(dominance_bids) == 1
    dominance_action = dominance_bids[0].action
    assert dominance_action.capsule_id == "path:0"
    assert dominance_action.owner is EvidenceOwner.FRONTIER
    assert dominance_action.may_remove_work is True
    assert dominance_action.requires_exact_evidence is True


def test_select_deterministic_bid_rejects_over_budget_actions() -> None:
    """The shadow policy cannot select actions exceeding the active budget."""
    over_budget = _bid("over", budget=BudgetVector(wall_time_ms=10.0, path_budget=1))
    accepted = _bid("accepted", budget=BudgetVector(wall_time_ms=1.0, path_budget=1), gain=2.0)

    decision = select_deterministic_bid(
        [over_budget, accepted],
        active_budget=BudgetVector(wall_time_ms=2.0, path_budget=1),
    )

    assert decision is not None
    assert decision.selected_bid.action.action_id == "accepted"
    assert decision.rejected_action_ids == ("over",)


def test_select_deterministic_bid_rejects_work_removal_without_exact_evidence() -> None:
    """Work-removing bids must require exact owner evidence before selection."""
    unsafe_prune = _bid(
        "unsafe",
        kind=EvidenceActionKind.CHECK_DOMINANCE,
        may_remove_work=True,
        requires_exact_evidence=False,
        gain=100.0,
    )

    decision = select_deterministic_bid(
        [unsafe_prune],
        active_budget=BudgetVector(path_budget=1),
    )

    assert decision is None
    assert unsafe_prune.action.is_sound_for_selection is False


def test_select_deterministic_bid_is_stable_for_equal_scores() -> None:
    """Tie-breaking is deterministic across capsule and action identities."""
    later = _bid("b", capsule_id="capsule-b")
    earlier = _bid("a", capsule_id="capsule-a")

    decision = select_deterministic_bid(
        [later, earlier],
        active_budget=BudgetVector(path_budget=1),
    )

    assert decision is not None
    assert decision.selected_bid.action.action_id == "a"
